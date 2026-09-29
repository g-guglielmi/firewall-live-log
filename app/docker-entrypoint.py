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

PUID / PGID (default 10001) select the runtime user, Unraid-style. Zero is
refused: the whole point of this entrypoint is that the app never runs as
root.

The ownership fix-up is confined to the data tree (/data) and to separately
mounted volumes; it never recurses into a system directory, so a mistyped
DB_PATH=/etc/events.db cannot hand /etc to the runtime user.
"""
import os
import posixpath
import stat
import sys

APP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py")
DATA_ROOT = "/data"
# Never chown into these, whatever a *_PATH variable says. "/" covers a path
# like DB_PATH=/events.db, whose parent is the root filesystem.
SYSTEM_DIRS = ("/", "/proc", "/sys", "/dev", "/etc", "/usr", "/bin", "/sbin",
               "/lib", "/lib64", "/boot", "/run", "/var", "/root", "/app",
               "/tmp", "/home")


def _env(name, default):
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def _canon(path):
    # realpath resolves symlinks (a link inside a volume must not redirect the
    # check); the nt branch only exists so the logic is unit-testable off-Linux.
    p = os.path.realpath(path) if os.name != "nt" else path
    return posixpath.normpath(p.replace("\\", "/"))


def _under(path, root):
    root = root.rstrip("/") or "/"
    return path == root or path.startswith(root + "/") or root == "/"


def chown_allowed(path):
    """True only for the data tree or a separately mounted, non-system volume.
    ``_under(real, "/")`` is always true, so the "/" entry in SYSTEM_DIRS
    is checked after the data-tree test and rejects any other location that
    isn't its own mount point."""
    real = _canon(path)
    if real == DATA_ROOT or real.startswith(DATA_ROOT + "/"):
        return True
    for d in SYSTEM_DIRS:
        if d != "/" and _under(real, d):
            return False
    return real != "/" and os.path.ismount(real)


def runtime_ids():
    """(uid, gid) from PUID/PGID; refuses 0 and non-numeric values."""
    try:
        uid = int(_env("PUID", "10001"))
        gid = int(_env("PGID", "10001"))
    except ValueError:
        raise SystemExit("[entrypoint] PUID/PGID must be numeric")
    if uid == 0 or gid == 0:
        raise SystemExit("[entrypoint] refusing to run the app as root: PUID "
                         "and PGID must be non-zero (default 10001)")
    return uid, gid


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
    uid, gid = runtime_ids()

    # Everything the app writes lives under these directories.
    dirs = {DATA_ROOT}
    for var, default in (("DB_PATH", "/data/events.db"),
                         ("AUTH_DB_PATH", "/data/auth.db"),
                         ("DEVICES_CONFIG", "/data/devices.json"),
                         ("LAYOUT_PATH", "")):
        p = _env(var, default)
        if p:
            dirs.add(os.path.dirname(p) or DATA_ROOT)
    for d in sorted(dirs):
        if not chown_allowed(d):
            print(f"[entrypoint] not fixing ownership of {d}: outside "
                  f"{DATA_ROOT} and not a mounted volume — make it writable "
                  f"by uid {uid} yourself", file=sys.stderr)
            continue
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
