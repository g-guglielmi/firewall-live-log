"""Background CSV exports.

A filtered export over a long window can take many minutes on a big
database (a substring filter can't use an index, so the whole range is
read). Instead of holding an HTTP response open for that long, the
dashboard starts an export job here: a worker thread scans the range on
its *own* read-only connection (so it never queues behind, or blocks, the
table's queries on the shared reader), writes the CSV to the data folder
and reports progress until the browser fetches the finished file.

Large results are split into parts of PART_ROWS rows (each one still opens
in a spreadsheet); more than one part is delivered as a ZIP. MAX_PARTS
bounds the disk an export may use; a job that reaches it says which time
span its files cover.
"""

import os
import re
import secrets
import shutil
import threading
import time
import zipfile

import store

PART_ROWS = 500_000
MAX_PARTS = 10
MAX_RUNNING = 2
KEEP_SEC = 15 * 60              # finished files are deleted after this
PAGE = 10_000


class ExportBusy(Exception):
    pass


class ExportJob:
    def __init__(self, owner, start_ts, end_ts, filters):
        self.id = secrets.token_hex(8)
        self.owner = owner
        self.start_ts, self.end_ts = start_ts, end_ts
        self.filters = {k: v for k, v in filters.items() if v}
        self.state = "running"          # running | done | failed
        self.created = time.time()
        self.finished = None
        self.rows = 0
        self.parts = 0
        self.progress = 0.0             # share of the id range scanned
        self.reached_ts = None          # oldest time scanned so far
        self.newest_ts = self.oldest_ts = None   # span of the rows written
        self.truncated = False
        self.error = None
        self.path = None                # finished file
        self.filename = None
        self.max_rows = self.part_rows = None
        self.cancel = threading.Event()

    def public(self):
        return {"id": self.id, "state": self.state, "rows": self.rows,
                "parts": self.parts, "progress": round(self.progress, 4),
                "reached_ts": self.reached_ts, "start_ts": self.start_ts,
                "end_ts": self.end_ts, "filters": self.filters,
                "newest_ts": self.newest_ts, "oldest_ts": self.oldest_ts,
                "truncated": self.truncated, "error": self.error,
                "filename": self.filename, "max_rows": self.max_rows,
                "part_rows": self.part_rows}


def _safe_name(s):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s or "")[:60].strip("._") or "all"


class ExportManager:
    def __init__(self, db_path, work_dir, to_csv, part_rows=PART_ROWS,
                 max_parts=MAX_PARTS, max_running=MAX_RUNNING,
                 keep_sec=KEEP_SEC, scan_span=store.WINDOW_SCAN_SPAN,
                 page=PAGE):
        self.db_path = db_path
        self.work_dir = work_dir
        self.to_csv = to_csv            # (events, header) -> str
        self.part_rows, self.max_parts = part_rows, max_parts
        self.max_running, self.keep_sec = max_running, keep_sec
        self.scan_span, self.page = scan_span, page
        self.lock = threading.Lock()
        self.jobs = {}
        # Leftovers from a previous run (container restart mid-export) are
        # never going to be fetched: start clean.
        shutil.rmtree(work_dir, ignore_errors=True)
        os.makedirs(work_dir, mode=0o700, exist_ok=True)

    # -- API used by the web handlers ---------------------------------------
    def start(self, owner, start_ts, end_ts, filters):
        self.sweep()
        with self.lock:
            running = sum(1 for j in self.jobs.values()
                          if j.state == "running")
            if running >= self.max_running:
                raise ExportBusy(f"{running} exports are already running; "
                                 "wait for one to finish or cancel it")
            job = ExportJob(owner, start_ts, end_ts, filters)
            job.part_rows = self.part_rows
            job.max_rows = self.part_rows * self.max_parts
            self.jobs[job.id] = job
        threading.Thread(target=self._run, args=(job,), daemon=True,
                         name=f"export-{job.id}").start()
        return job

    def list(self, owner):
        self.sweep()
        with self.lock:
            return sorted((j for j in self.jobs.values() if j.owner == owner),
                          key=lambda j: j.created)

    def get(self, owner, job_id):
        with self.lock:
            job = self.jobs.get(job_id)
        return job if job and job.owner == owner else None

    def remove(self, owner, job_id):
        """Cancel a running job, or discard a finished one and its file."""
        with self.lock:
            job = self.jobs.get(job_id)
            if not job or job.owner != owner:
                return False
            del self.jobs[job_id]
        job.cancel.set()                # the worker cleans up its own files
        if job.state != "running":
            self._delete_files(job)
        return True

    def start_sweeper(self, interval=60):
        def loop():
            while True:
                time.sleep(interval)
                self.sweep()
        threading.Thread(target=loop, daemon=True,
                         name="export-sweeper").start()

    def sweep(self, now=None):
        now = now or time.time()
        with self.lock:
            old = [j for j in self.jobs.values()
                   if j.finished and now - j.finished > self.keep_sec]
            for j in old:
                del self.jobs[j.id]
        for j in old:
            self._delete_files(j)

    # -- worker ---------------------------------------------------------------
    def _job_dir(self, job):
        return os.path.join(self.work_dir, job.id)

    def _delete_files(self, job):
        shutil.rmtree(self._job_dir(job), ignore_errors=True)

    def _run(self, job):
        jdir = self._job_dir(job)
        os.makedirs(jdir, mode=0o700, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M")
        base = f"firewall-log-{_safe_name(job.filters.get('device'))}-{stamp}"
        part_paths, out, in_part = [], None, 0
        db = None
        try:
            db = store.open_reader(self.db_path)
            lo_row = db.execute(
                "SELECT id FROM events WHERE ts >= ? ORDER BY ts LIMIT 1",
                (job.start_ts,)).fetchone()
            if job.end_ts is not None:
                hi_row = db.execute(
                    "SELECT id FROM events WHERE ts > ? ORDER BY ts LIMIT 1",
                    (job.end_ts,)).fetchone()
            else:
                hi_row = None
            top = hi_row[0] if hi_row else db.execute(
                "SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
            lo = lo_row[0] if lo_row else top
            span = max(top - lo, 1)
            cap = self.part_rows * self.max_parts
            before, more = None, True
            while more and job.rows < cap:
                if job.cancel.is_set():
                    return
                events, more, before = store.query_range(
                    db, job.start_ts, job.end_ts, job.filters,
                    min(self.page, cap - job.rows), before=before,
                    scan_span=self.scan_span)
                i = 0
                while i < len(events):
                    if out is None or in_part >= self.part_rows:
                        if out:
                            out.close()
                        part_paths.append(os.path.join(
                            jdir, f"{base}-part{len(part_paths) + 1:02d}.csv"))
                        out = open(part_paths[-1], "w", encoding="utf-8",
                                   newline="")
                        out.write(self.to_csv([], header=True))
                        in_part = 0
                    chunk = events[i:i + self.part_rows - in_part]
                    out.write(self.to_csv(chunk, header=False))
                    in_part += len(chunk)
                    i += len(chunk)
                if events:
                    job.newest_ts = job.newest_ts or events[0]["ts"]
                    job.oldest_ts = events[-1]["ts"]
                    job.rows += len(events)
                job.parts = len(part_paths)
                if more and before:
                    job.progress = min(1.0, (top - before) / span)
                    r = db.execute("SELECT ts FROM events WHERE id <= ? "
                                   "ORDER BY id DESC LIMIT 1",
                                   (before,)).fetchone()
                    job.reached_ts = r[0] if r else job.start_ts
            job.truncated = bool(more and job.rows >= cap)
            if out is None:             # no match at all: header-only file
                part_paths.append(os.path.join(jdir, base + ".csv"))
                with open(part_paths[-1], "w", encoding="utf-8",
                          newline="") as f:
                    f.write(self.to_csv([], header=True))
            else:
                out.close()
                out = None
            if len(part_paths) == 1:
                final = os.path.join(jdir, base + ".csv")
                os.replace(part_paths[0], final)
            else:
                final = os.path.join(jdir, base + ".zip")
                with zipfile.ZipFile(final, "w", zipfile.ZIP_DEFLATED,
                                     allowZip64=True) as z:
                    for p in part_paths:
                        if job.cancel.is_set():
                            return
                        z.write(p, os.path.basename(p))
                        os.remove(p)
            job.parts = len(part_paths)
            job.path, job.filename = final, os.path.basename(final)
            job.progress = 1.0
            job.state = "done"
        except Exception as e:          # noqa: BLE001 — reported to the user
            job.state, job.error = "failed", "the export could not be completed"
            print(f"[export] {job.id} failed: {type(e).__name__}: {e}",
                  flush=True)
        finally:
            if out:
                out.close()
            if db:
                db.close()
            job.finished = time.time()
            if job.cancel.is_set() or job.state == "failed":
                self._delete_files(job)
