#!/usr/bin/env python3
"""Container entrypoint: make the data directory usable, then drop root.

Started as root (the image default), it chowns the data directories to the
runtime user and then replaces itself with the app running as that user.
Root exists for milliseconds, touches nothing but data-dir ownership, and
no socket is opened nor any byte of input parsed before the privileges are
dropped. This removes the classic first-run failure where the host's data
folder (e.g. Unraid appdata created by root) is not writable by the app's
unprivileged user.

Started with --user (any non-root uid), the fix-up is skipped entirely and
the app simply runs as that user — the strict never-root mode. The data
folder must then be writable by that user (chown it on the host).

PUID / PGID (default 10001) select the runtime user, Unraid-style.
"""
import os
import stat
import sys

APP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py")


def _env(name, default):
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def _chown_tree(path, uid, gid):
    """chown path — and, for a directory, everything inside — to uid:gid,
    skipping entries already owned correctly. Symlinks are changed but never
    followed, so a link inside the volume can't redirect the chown outside."""
    try:
        st = os.lstat(path)
    except OSError:
        return
    if st.st_uid != uid or st.st_gid != gid:
        try:
            os.lchown(path, uid, gid)
        except OSError as e:
            print(f"[entrypoint] warning: cannot chown {path}: {e}",
                  file=sys.stderr)
            return
    if stat.S_ISDIR(st.st_mode):
        try:
            names = os.listdir(path)
        except OSError:
            return
        for name in names:
            _chown_tree(os.path.join(path, name), uid, gid)


def main():
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        # Strict mode (--user ...): never root, no ownership fix-up.
        os.execv(sys.executable, [sys.executable, APP])
    uid = int(_env("PUID", "10001"))
    gid = int(_env("PGID", "10001"))

    # Everything the app writes lives under these directories.
    dirs = {"/data"}
    for var, default in (("DB_PATH", "/data/events.db"),
                         ("AUTH_DB_PATH", "/data/auth.db"),
                         ("LAYOUT_PATH", "")):
        p = _env(var, default)
        if p:
            dirs.add(os.path.dirname(p) or "/data")
    for d in sorted(dirs):
        try:
            os.makedirs(d, exist_ok=True)
        except OSError as e:
            print(f"[entrypoint] warning: cannot create {d}: {e}",
                  file=sys.stderr)
            continue
        _chown_tree(d, uid, gid)

    # Drop privileges irrevocably, then become the app.
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    os.environ.setdefault("HOME", "/data")
    os.execv(sys.executable, [sys.executable, APP])


if __name__ == "__main__":
    main()
