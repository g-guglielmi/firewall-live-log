"""SQLite storage for the live log — one row per event, with time-based
retention and an optional row cap.

Concurrency model: a single writer thread owns the read-write connection
(SQLite allows only one writer); HTTP handler threads share one read-only
connection guarded by a lock.  WAL mode lets reads proceed during writes.
"""

import sqlite3
import time

SCHEMA_VERSION = "1"

COLUMNS = ("id", "ts", "device", "vendor", "src", "dst", "proto",
           "dst_port", "action", "rule")

INSERT_EVENT = """
    INSERT INTO events (ts, device, vendor, src, dst, proto, dst_port,
                        action, rule)
    VALUES (?,?,?,?,?,?,?,?,?)
"""


def open_writer(path):
    db = sqlite3.connect(path, timeout=30, check_same_thread=False)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    # auto_vacuum must be set before the schema is created on a fresh file;
    # it lets incremental_vacuum reclaim space after retention deletes.
    db.execute("PRAGMA auto_vacuum=INCREMENTAL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ts       INTEGER NOT NULL,
            device   TEXT    NOT NULL,
            vendor   TEXT    NOT NULL,
            src      TEXT    NOT NULL,
            dst      TEXT    NOT NULL,
            proto    TEXT    NOT NULL,
            dst_port INTEGER NOT NULL,   -- -1 sentinel for ICMP / no port
            action   TEXT    NOT NULL,   -- Allow / Block / Drop / Reject / NAT / ?
            rule     TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_events_dev ON events(device, id);
        CREATE TABLE IF NOT EXISTS unparsed (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL, device TEXT NOT NULL, raw TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
    """)
    db.execute("INSERT OR REPLACE INTO meta VALUES ('schema_version', ?)",
               (SCHEMA_VERSION,))
    db.commit()
    return db


def open_reader(path):
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10,
                           check_same_thread=False)


def meta_get(db, key, default=None):
    row = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def meta_set(db, key, value):
    db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, str(value)))


def insert_events(db, rows):
    if rows:
        db.executemany(INSERT_EVENT, rows)


def insert_unparsed(db, rows):
    if rows:
        db.executemany(
            "INSERT INTO unparsed (ts, device, raw) VALUES (?,?,?)", rows)


def prune(db, retention_days, max_events, unparsed_cap=10000):
    """Delete events past the retention window / row cap; reclaim space."""
    cutoff = int(time.time()) - int(retention_days) * 86400
    db.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
    if max_events and max_events > 0:
        db.execute(
            "DELETE FROM events WHERE id <= "
            "COALESCE((SELECT MAX(id) FROM events), 0) - ?", (max_events,))
    db.execute("DELETE FROM unparsed WHERE id <= "
               "COALESCE((SELECT MAX(id) FROM unparsed), 0) - ?",
               (unparsed_cap,))
    db.commit()
    db.execute("PRAGMA incremental_vacuum")
    db.commit()


# --------------------------------------------------------------------------
# Read queries (reader connection)
# --------------------------------------------------------------------------
_BLOCK_ACTIONS = ("Block", "Drop", "Reject")


def _filter_clauses(f):
    """Build (clauses, args) from a filter dict for device/vendor/ip/port/action."""
    clauses, args = [], []
    if f.get("device"):
        clauses.append("device = ?")
        args.append(f["device"])
    if f.get("vendor"):
        clauses.append("vendor = ?")
        args.append(f["vendor"])
    if f.get("ip"):
        clauses.append("(src LIKE ? OR dst LIKE ?)")
        like = f"%{f['ip']}%"
        args += [like, like]
    if f.get("port"):
        # Prefix match so the result narrows as the user types ("44"
        # matches 443 and 445), mirroring the substring IP filter.  A
        # leading "=" forces an exact match ("=80" excludes 8080).
        port = str(f["port"])
        if port.startswith("="):
            clauses.append("dst_port = ?")
            args.append(int(port[1:]))
        else:
            clauses.append("CAST(dst_port AS TEXT) LIKE ?")
            args.append(port + "%")
    action = f.get("action")
    if action == "blocked":
        clauses.append("action IN (?,?,?)")
        args += list(_BLOCK_ACTIONS)
    elif action:
        clauses.append("action = ?")
        args.append(action)
    return clauses, args


def _rows_to_dicts(rows):
    return [dict(zip(COLUMNS, r)) for r in rows]


_SELECT = ("SELECT id, ts, device, vendor, src, dst, proto, dst_port, "
           "action, rule FROM events")


def query_live(db, since, filters, limit):
    """Incremental tail: events with id > since (or the most recent when
    since<=0), oldest-first.  Returns (cursor, [event dicts])."""
    clauses, args = _filter_clauses(filters)
    if since and since > 0:
        clauses.append("id > ?")
        args.append(since)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = db.execute(f"{_SELECT}{where} ORDER BY id ASC LIMIT ?",
                          args + [limit]).fetchall()
        cursor = rows[-1][0] if rows else since
    else:
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = db.execute(f"{_SELECT}{where} ORDER BY id DESC LIMIT ?",
                          args + [limit]).fetchall()
        rows = rows[::-1]
        # Cursor = newest id actually returned, so the next incremental poll
        # (id > cursor) picks up strictly newer events with no skip and no
        # re-send. Fall back to MAX(id) only when nothing matched, so a live
        # filter with no recent hits still tails from "now" forward.
        if rows:
            cursor = rows[-1][0]
        else:
            cursor = db.execute(
                "SELECT COALESCE(MAX(id),0) FROM events").fetchone()[0]
    return cursor, _rows_to_dicts(rows)


def query_window(db, window_secs, filters, limit):
    """Historical snapshot: matching events within the last window_secs,
    newest-first."""
    clauses, args = _filter_clauses(filters)
    clauses.append("ts >= ?")
    args.append(int(time.time()) - int(window_secs))
    where = " WHERE " + " AND ".join(clauses)
    rows = db.execute(f"{_SELECT}{where} ORDER BY id DESC LIMIT ?",
                      args + [limit]).fetchall()
    return _rows_to_dicts(rows)
