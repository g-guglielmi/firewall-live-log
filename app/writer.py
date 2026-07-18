"""The single DB-writer thread.

Drains the shared queue, batch-inserts events (and unparsed lines) every
FLUSH_INTERVAL, prunes to the retention window every PRUNE_INTERVAL, and
publishes counters to the meta table.  On shutdown it drains whatever is
left so a container stop loses nothing.
"""

import queue
import sys
import time

import store

FLUSH_INTERVAL = 1.0
STATS_INTERVAL = 60.0


def run(stop_event, db_path, q, drops, cfg, prune_interval):
    db = store.open_writer(db_path)
    counters = {"parsed": int(store.meta_get(db, "stat_parsed", "0")),
                "unparsed": int(store.meta_get(db, "stat_unparsed", "0"))}

    events, unparsed = [], []
    last_flush = last_prune = last_stats = time.monotonic()

    def flush():
        if events:
            store.insert_events(db, events)
            counters["parsed"] += len(events)
            events.clear()
        if unparsed:
            store.insert_unparsed(db, unparsed)
            counters["unparsed"] += len(unparsed)
            unparsed.clear()
        store.meta_set(db, "stat_parsed", counters["parsed"])
        store.meta_set(db, "stat_unparsed", counters["unparsed"])
        with drops["lock"]:
            store.meta_set(db, "stat_dropped", drops["n"])
        db.commit()

    # Prune once at startup so a restart immediately honors retention.
    store.prune(db, cfg.retention_days, cfg.max_events)

    while not stop_event.is_set():
        try:
            item = q.get(timeout=0.5)
            if item[0] == "ev":
                events.append(item[1:])           # (ts, device, vendor, ...)
            else:
                unparsed.append(item[1:])          # (ts, device, raw)
        except queue.Empty:
            pass

        mono = time.monotonic()
        if mono - last_flush >= FLUSH_INTERVAL or len(events) >= 2000:
            flush()
            last_flush = mono
        if mono - last_prune >= prune_interval:
            store.prune(db, cfg.retention_days, cfg.max_events)
            last_prune = mono
        if mono - last_stats >= STATS_INTERVAL:
            print(f"[writer] parsed={counters['parsed']} "
                  f"unparsed={counters['unparsed']} dropped={drops['n']} "
                  f"qdepth={q.qsize()}")
            sys.stdout.flush()
            last_stats = mono

    # Final drain: flush everything already queued at shutdown. (A datagram
    # a listener receives in the <=1s after stop_event is set may arrive
    # after this drain — inherent to best-effort UDP syslog.)
    while True:
        try:
            item = q.get_nowait()
        except queue.Empty:
            break
        if item[0] == "ev":
            events.append(item[1:])
        else:
            unparsed.append(item[1:])
    flush()
    db.close()
    print(f"[writer] stopped cleanly; parsed={counters['parsed']} total")
    sys.stdout.flush()
