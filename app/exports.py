"""Background CSV exports: a queue, run one at a time, kept for hours.

A filtered export over a long window can take many minutes on a big
database (a substring filter that the rule index can't serve reads every
event in the range). Instead of holding an HTTP response open for that
long, the dashboard queues an export job here. One worker thread runs the
queue in order — two scans at once would only compete for the same disk —
on its *own* read-only connection, so it never queues behind, or blocks,
the table's queries on the shared reader. The CSV is written to the data
folder and kept for KEEP_SEC so it can be fetched (again) later.

Large results are split into parts of PART_ROWS rows (each one still opens
in a spreadsheet); more than one part is delivered as a ZIP. MAX_PARTS
bounds what one export may write and MAX_BYTES what all stored exports may
occupy together (the oldest finished ones make room).

Every job keeps a small manifest (job.json) next to its file, so finished
exports survive a container restart, and queued or interrupted ones are
run again from the start (at most MAX_ATTEMPTS times).
"""

import json
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
MAX_QUEUED_PER_USER = 10
KEEP_SEC = 8 * 3600
MAX_BYTES = 2 * 1024 ** 3
MAX_ATTEMPTS = 3
PAGE = 10_000
_ID_RE = re.compile(r"[0-9a-f]{16}")
_SAVED = ("id", "owner", "start_ts", "end_ts", "filters", "state",
          "created", "started", "finished", "rows", "parts", "newest_ts",
          "oldest_ts", "truncated", "error", "filename", "size", "attempts",
          "max_rows", "part_rows")


class ExportBusy(Exception):
    pass


class ExportJob:
    def __init__(self, owner, start_ts, end_ts, filters):
        self.id = secrets.token_hex(8)
        self.owner = owner
        self.start_ts, self.end_ts = start_ts, end_ts
        self.filters = {k: v for k, v in filters.items() if v}
        # queued | running | done | failed | removed (evicted for space)
        self.state = "queued"
        self.created = time.time()
        self.started = self.finished = None
        self.rows = 0
        self.parts = 0
        self.progress = 0.0             # share of the id range scanned
        self.reached_ts = None          # oldest time scanned so far
        self.newest_ts = self.oldest_ts = None   # span of the rows written
        self.truncated = False
        self.error = None
        self.filename = None
        self.size = 0
        self.attempts = 0
        self.max_rows = self.part_rows = None
        self.cancel = threading.Event()

    def public(self, position=None):
        d = {k: getattr(self, k) for k in _SAVED if k != "owner"}
        d.update(progress=round(self.progress, 4), reached_ts=self.reached_ts,
                 position=position)
        return d


def _safe_name(s):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s or "")[:60].strip("._") or "all"


class ExportManager:
    def __init__(self, db_path, work_dir, to_csv, part_rows=PART_ROWS,
                 max_parts=MAX_PARTS, max_queued=MAX_QUEUED_PER_USER,
                 keep_sec=KEEP_SEC, max_bytes=MAX_BYTES,
                 scan_span=store.WINDOW_SCAN_SPAN, page=PAGE, autostart=True):
        self.db_path = db_path
        self.work_dir = work_dir
        self.to_csv = to_csv            # (events, header) -> str
        self.part_rows, self.max_parts = part_rows, max_parts
        self.max_queued, self.keep_sec = max_queued, keep_sec
        self.max_bytes = max_bytes
        self.scan_span, self.page = scan_span, page
        self.lock = threading.Lock()
        self.wake = threading.Condition(self.lock)
        self.jobs = {}
        os.makedirs(work_dir, mode=0o700, exist_ok=True)
        self._restore()
        if autostart:
            threading.Thread(target=self._worker, daemon=True,
                             name="export-worker").start()

    # -- persistence -----------------------------------------------------------
    def _job_dir(self, job_id):
        return os.path.join(self.work_dir, job_id)

    def _save(self, job):
        path = os.path.join(self._job_dir(job.id), "job.json")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({k: getattr(job, k) for k in _SAVED}, f)
        os.replace(tmp, path)

    def _delete_files(self, job_id):
        shutil.rmtree(self._job_dir(job_id), ignore_errors=True)

    def _drop_outputs(self, job_id):
        """Remove a job's data files but keep its manifest."""
        jdir = self._job_dir(job_id)
        for f in os.listdir(jdir):
            if f != "job.json":
                try:
                    os.remove(os.path.join(jdir, f))
                except OSError:
                    pass

    def _restore(self):
        """Pick up the exports a previous run left: finished ones stay
        downloadable, queued or interrupted ones go back in the queue (from
        the start, partial files dropped), anything unreadable is removed."""
        for name in sorted(os.listdir(self.work_dir)):
            jdir = self._job_dir(name)
            try:
                if not _ID_RE.fullmatch(name):
                    raise ValueError("not an export")
                with open(os.path.join(jdir, "job.json"),
                          encoding="utf-8") as f:
                    saved = json.load(f)
                job = ExportJob(saved["owner"], saved["start_ts"],
                                saved["end_ts"], saved["filters"])
                for k in _SAVED:
                    if k in saved:
                        setattr(job, k, saved[k])
                if job.id != name:
                    raise ValueError("manifest does not match its folder")
            except (OSError, ValueError, KeyError, TypeError):
                if os.path.isdir(jdir):
                    shutil.rmtree(jdir, ignore_errors=True)
                else:
                    try:
                        os.remove(jdir)
                    except OSError:
                        pass
                continue
            if job.state in ("queued", "running"):
                self._drop_outputs(job.id)
                if job.attempts >= MAX_ATTEMPTS:
                    job.state, job.finished = "failed", time.time()
                    job.error = ("the export was interrupted by "
                                 f"{job.attempts} restarts; start it again "
                                 "with a smaller range")
                else:
                    job.state = "queued"
                job.rows = job.parts = 0
                job.newest_ts = job.oldest_ts = None
                self._save(job)
            elif job.state == "done" and not (
                    job.filename and os.path.exists(
                        os.path.join(jdir, job.filename))):
                self._delete_files(job.id)
                continue
            self.jobs[job.id] = job
        self.sweep()

    # -- API used by the web handlers ---------------------------------------
    def start(self, owner, start_ts, end_ts, filters):
        self.sweep()
        with self.lock:
            waiting = sum(1 for j in self.jobs.values() if j.owner == owner
                          and j.state in ("queued", "running"))
            if waiting >= self.max_queued:
                raise ExportBusy(f"you already have {waiting} exports queued "
                                 "or running; wait for one to finish or "
                                 "cancel it")
            job = ExportJob(owner, start_ts, end_ts, filters)
            job.part_rows = self.part_rows
            job.max_rows = self.part_rows * self.max_parts
            os.makedirs(self._job_dir(job.id), mode=0o700, exist_ok=True)
            self._save(job)
            self.jobs[job.id] = job
            self.wake.notify_all()
        return job

    def _position(self, job):
        """1 = next to run. Counts every user's waiting exports."""
        if job.state != "queued":
            return None
        return sum(1 for j in self.jobs.values()
                   if j.state == "running" or (j.state == "queued"
                                               and j.created <= job.created))

    def list(self, owner):
        """[(job, queue position or None)] for this owner, newest first."""
        self.sweep()
        with self.lock:
            mine = sorted((j for j in self.jobs.values() if j.owner == owner),
                          key=lambda j: j.created, reverse=True)
            return [(j, self._position(j)) for j in mine]

    def get(self, owner, job_id):
        with self.lock:
            job = self.jobs.get(job_id)
            if job and job.owner == owner:
                return job, self._position(job)
        return None, None

    def remove(self, owner, job_id):
        """Cancel a queued or running export, or delete a finished one."""
        with self.lock:
            job = self.jobs.get(job_id)
            if not job or job.owner != owner:
                return False
            del self.jobs[job_id]
            running = job.state == "running"
            job.cancel.set()            # a running worker drops its files
        if not running:
            self._delete_files(job_id)
        return True

    def sweep(self, now=None):
        now = now or time.time()
        with self.lock:
            old = [j for j in self.jobs.values()
                   if j.finished and now - j.finished > self.keep_sec]
            for j in old:
                del self.jobs[j.id]
        for j in old:
            self._delete_files(j.id)

    def stored_bytes(self):
        with self.lock:
            return sum(j.size for j in self.jobs.values() if j.state == "done")

    def _make_room(self, keep):
        """Delete the oldest finished files until the stored exports fit in
        max_bytes again. The export that just finished is never the one to
        go; the evicted ones stay listed (as removed) until they expire."""
        with self.lock:
            done = sorted((j for j in self.jobs.values()
                           if j.state == "done" and j is not keep),
                          key=lambda j: j.finished or 0)
            total = sum(j.size for j in done) + keep.size
            evict = []
            while done and total > self.max_bytes:
                j = done.pop(0)
                total -= j.size
                evict.append(j)
            for j in evict:
                j.state, j.size = "removed", 0
                j.error = ("deleted to make room for newer exports "
                           f"({self.max_bytes / 1024 ** 3:g} GB limit)")
        for j in evict:
            self._drop_outputs(j.id)
            self._save(j)

    # -- worker ---------------------------------------------------------------
    def _next_job(self):
        with self.lock:
            queued = sorted((j for j in self.jobs.values()
                             if j.state == "queued"), key=lambda j: j.created)
            if not queued:
                return None
            job = queued[0]
            job.state, job.started = "running", time.time()
            job.attempts += 1
            self._save(job)
            return job

    def _worker(self):
        while True:
            self.sweep()
            job = self._next_job()
            if job is None:
                with self.lock:
                    if not any(j.state == "queued"
                               for j in self.jobs.values()):
                        self.wake.wait(timeout=60)
                continue
            self.run(job)

    def run_pending(self):
        """Run the queue to empty on the calling thread (tests)."""
        while True:
            job = self._next_job()
            if job is None:
                return
            self.run(job)

    def run(self, job):
        """Run one job to completion."""
        jdir = self._job_dir(job.id)
        os.makedirs(jdir, mode=0o700, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M", time.localtime(job.created))
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
            job.filename = os.path.basename(final)
            job.size = os.path.getsize(final)
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
            if job.cancel.is_set():
                self._delete_files(job.id)
            else:
                if job.state == "failed":
                    self._drop_outputs(job.id)
                self._save(job)
                if job.state == "done":
                    self._make_room(job)

    def path_of(self, job):
        return os.path.join(self._job_dir(job.id), job.filename)
