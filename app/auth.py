"""Authentication for the dashboard — users, sessions, and brute-force
lockout, using only the Python standard library.

Storage is a dedicated SQLite file (``auth.db``) with its own read/write
connection and a lock, kept separate from the events database so it never
contends with the single writer thread that owns ``events.db``.

Security properties:
  * Passwords are stored as PBKDF2-HMAC-SHA256 (600k iterations, 16-byte
    random salt) — never in clear text and never reversibly.
  * Every SQL statement is parameterised; no user input is ever formatted
    into SQL, so the store is not injectable.
  * Session tokens and CSRF tokens come from ``secrets``; only the SHA-256
    of the session token is persisted, so a leaked DB does not leak live
    tokens. Verification uses constant-time comparisons.
  * Login is rate-limited: five failed attempts for a username within a
    15-minute window locks that username until the window slides; a more
    lenient per-IP backstop catches username-spraying. Unknown usernames
    still run a dummy hash so response time does not reveal whether a user
    exists.
"""

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
import threading
import time

# --- Tunables -------------------------------------------------------------
PBKDF2_ITERATIONS = 600_000          # OWASP 2023 floor for PBKDF2-SHA256
SESSION_TTL_SEC = 12 * 3600          # sessions expire after 12h
LOCKOUT_THRESHOLD = 5                # failed logins per username...
LOCKOUT_WINDOW_SEC = 15 * 60         # ...within this window -> locked
IP_LOCKOUT_THRESHOLD = 50            # lenient per-IP anti-spray backstop
ATTEMPT_RETENTION_SEC = 24 * 3600    # keep login attempts this long
MIN_PASSWORD_LEN = 12
VALID_ROLES = ("admin", "user")

_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{2,63}$")

# A fixed hash of a throwaway password. verify_login() runs a PBKDF2 pass
# against this when the username is unknown, so a missing user and a wrong
# password take the same time (no user enumeration via timing).
_DUMMY_HASH = None


class AuthError(Exception):
    """Raised for caller-fixable problems (bad input, duplicate user).

    ``code`` is an HTTP-ish status the web layer can surface directly.
    """

    def __init__(self, message, code=400):
        super().__init__(message)
        self.code = code


def _b64e(b):
    return base64.b64encode(b).decode("ascii")


def _b64d(s):
    return base64.b64decode(s.encode("ascii"))


def hash_password(password, iterations=PBKDF2_ITERATIONS, salt=None):
    """Return a self-describing ``pbkdf2_sha256$iters$salt$hash`` string."""
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                             iterations)
    return f"pbkdf2_sha256${iterations}${_b64e(salt)}${_b64e(dk)}"


def verify_password(password, stored):
    """Constant-time verify of ``password`` against a stored hash string."""
    try:
        algo, iters, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 _b64d(salt_b64), int(iters))
        return hmac.compare_digest(dk, _b64d(hash_b64))
    except (ValueError, TypeError):
        return False


def _validate_username(username):
    if not isinstance(username, str) or not _USERNAME_RE.match(username):
        raise AuthError(
            "username must be 3-64 chars, start alphanumeric, and use only "
            "letters, digits, and . _ - @")
    return username


def _validate_password(password):
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LEN:
        raise AuthError(
            f"password must be at least {MIN_PASSWORD_LEN} characters")
    if len(password) > 1024:
        raise AuthError("password too long")
    return password


def _token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class AuthManager:
    def __init__(self, db_path):
        global _DUMMY_HASH
        self.lock = threading.Lock()
        self.db = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                username       TEXT NOT NULL UNIQUE COLLATE NOCASE,
                pw_hash        TEXT NOT NULL,
                role           TEXT NOT NULL DEFAULT 'user',
                must_change_pw INTEGER NOT NULL DEFAULT 0,
                created_at     INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id    INTEGER NOT NULL,
                csrf_token TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_user
                ON sessions(user_id);
            CREATE TABLE IF NOT EXISTS login_attempts (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE,
                ip       TEXT NOT NULL,
                ts       INTEGER NOT NULL,
                success  INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_attempts_user_ts
                ON login_attempts(username, ts);
            CREATE INDEX IF NOT EXISTS idx_attempts_ip_ts
                ON login_attempts(ip, ts);
        """)
        self.db.commit()
        if _DUMMY_HASH is None:
            _DUMMY_HASH = hash_password(secrets.token_urlsafe(16))

    # -- users -------------------------------------------------------------
    def user_count(self):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def create_user(self, username, password, role="user",
                    must_change_pw=False):
        username = _validate_username(username)
        _validate_password(password)
        if role not in VALID_ROLES:
            raise AuthError(f"role must be one of {list(VALID_ROLES)}")
        pw_hash = hash_password(password)
        with self.lock:
            try:
                cur = self.db.execute(
                    "INSERT INTO users (username, pw_hash, role, "
                    "must_change_pw, created_at) VALUES (?,?,?,?,?)",
                    (username, pw_hash, role, 1 if must_change_pw else 0,
                     int(time.time())))
                self.db.commit()
                return cur.lastrowid
            except sqlite3.IntegrityError:
                raise AuthError(f"user {username!r} already exists", code=409)

    def _row_to_user(self, row):
        if not row:
            return None
        return {"id": row[0], "username": row[1], "role": row[3],
                "must_change_pw": bool(row[4]), "created_at": row[5],
                "_pw_hash": row[2]}

    def get_user_by_name(self, username):
        with self.lock:
            row = self.db.execute(
                "SELECT id, username, pw_hash, role, must_change_pw, "
                "created_at FROM users WHERE username = ? COLLATE NOCASE",
                (username,)).fetchone()
        return self._row_to_user(row)

    def get_user_by_id(self, user_id):
        with self.lock:
            row = self.db.execute(
                "SELECT id, username, pw_hash, role, must_change_pw, "
                "created_at FROM users WHERE id = ?", (user_id,)).fetchone()
        return self._row_to_user(row)

    def list_users(self):
        with self.lock:
            rows = self.db.execute(
                "SELECT id, username, role, must_change_pw, created_at "
                "FROM users ORDER BY id").fetchall()
        return [{"id": r[0], "username": r[1], "role": r[2],
                 "must_change_pw": bool(r[3]), "created_at": r[4]}
                for r in rows]

    def delete_user(self, user_id):
        with self.lock:
            row = self.db.execute("SELECT role FROM users WHERE id = ?",
                                  (user_id,)).fetchone()
            if not row:
                raise AuthError("user not found", code=404)
            if row[0] == "admin":
                admins = self.db.execute(
                    "SELECT COUNT(*) FROM users WHERE role = 'admin'"
                ).fetchone()[0]
                if admins <= 1:
                    raise AuthError("cannot delete the last admin", code=409)
            self.db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            self.db.execute("DELETE FROM sessions WHERE user_id = ?",
                            (user_id,))
            self.db.commit()

    def set_password(self, user_id, new_password, must_change_pw=False,
                     revoke_sessions=True):
        _validate_password(new_password)
        pw_hash = hash_password(new_password)
        with self.lock:
            cur = self.db.execute(
                "UPDATE users SET pw_hash = ?, must_change_pw = ? "
                "WHERE id = ?",
                (pw_hash, 1 if must_change_pw else 0, user_id))
            if cur.rowcount == 0:
                raise AuthError("user not found", code=404)
            if revoke_sessions:
                self.db.execute("DELETE FROM sessions WHERE user_id = ?",
                                (user_id,))
            self.db.commit()

    def set_role(self, user_id, role):
        if role not in VALID_ROLES:
            raise AuthError(f"role must be one of {list(VALID_ROLES)}")
        with self.lock:
            row = self.db.execute("SELECT role FROM users WHERE id = ?",
                                  (user_id,)).fetchone()
            if not row:
                raise AuthError("user not found", code=404)
            if row[0] == "admin" and role != "admin":
                admins = self.db.execute(
                    "SELECT COUNT(*) FROM users WHERE role = 'admin'"
                ).fetchone()[0]
                if admins <= 1:
                    raise AuthError("cannot demote the last admin", code=409)
            self.db.execute("UPDATE users SET role = ? WHERE id = ?",
                            (role, user_id))
            self.db.commit()

    # -- login + rate limiting --------------------------------------------
    def _recent_failures(self, column, value, now):
        return self.db.execute(
            f"SELECT COUNT(*), MIN(ts) FROM login_attempts "
            f"WHERE {column} = ? AND success = 0 AND ts >= ?",
            (value, now - LOCKOUT_WINDOW_SEC)).fetchone()

    def verify_login(self, username, password, ip):
        """Return ``(user_or_None, error_or_None, retry_after)``.

        ``retry_after`` is >0 only when the caller is locked out. On success
        the username's failed-attempt history is cleared.
        """
        now = int(time.time())
        if not isinstance(username, str) or not isinstance(password, str):
            return None, "username and password are required", 0
        # column is a fixed literal, never user input -> not injectable.
        with self.lock:
            u_count, u_oldest = self._recent_failures("username", username, now)
            i_count, i_oldest = self._recent_failures("ip", ip, now)
            locked_until = 0
            if u_count >= LOCKOUT_THRESHOLD and u_oldest:
                locked_until = max(locked_until, u_oldest + LOCKOUT_WINDOW_SEC)
            if i_count >= IP_LOCKOUT_THRESHOLD and i_oldest:
                locked_until = max(locked_until, i_oldest + LOCKOUT_WINDOW_SEC)
            if locked_until:
                return (None, "too many failed attempts; try again later",
                        max(1, locked_until - now))

            row = self.db.execute(
                "SELECT id, username, pw_hash, role, must_change_pw, "
                "created_at FROM users WHERE username = ? COLLATE NOCASE",
                (username,)).fetchone()
            user = self._row_to_user(row)
            if user is not None:
                ok = verify_password(password, user["_pw_hash"])
            else:
                # Equalise timing for unknown users.
                verify_password(password, _DUMMY_HASH)
                ok = False

            self.db.execute(
                "INSERT INTO login_attempts (username, ip, ts, success) "
                "VALUES (?,?,?,?)", (username, ip, now, 1 if ok else 0))
            if ok:
                self.db.execute(
                    "DELETE FROM login_attempts WHERE username = ? "
                    "COLLATE NOCASE AND success = 0", (username,))
            self.db.commit()

        if not ok:
            return None, "invalid username or password", 0
        return user, None, 0

    # -- sessions ----------------------------------------------------------
    def create_session(self, user_id):
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        now = int(time.time())
        with self.lock:
            self.db.execute(
                "INSERT INTO sessions (token_hash, user_id, csrf_token, "
                "created_at, expires_at) VALUES (?,?,?,?,?)",
                (_token_hash(token), user_id, csrf, now,
                 now + SESSION_TTL_SEC))
            self.db.commit()
        return token, csrf, now + SESSION_TTL_SEC

    def get_session(self, token):
        """Return ``(user, csrf_token)`` for a valid token, else ``None``."""
        if not token or not isinstance(token, str):
            return None
        th = _token_hash(token)
        now = int(time.time())
        with self.lock:
            row = self.db.execute(
                "SELECT s.user_id, s.csrf_token, s.expires_at, u.id, "
                "u.username, u.pw_hash, u.role, u.must_change_pw, "
                "u.created_at FROM sessions s JOIN users u "
                "ON u.id = s.user_id WHERE s.token_hash = ?", (th,)).fetchone()
            if not row:
                return None
            if row[2] < now:
                self.db.execute("DELETE FROM sessions WHERE token_hash = ?",
                                (th,))
                self.db.commit()
                return None
        user = {"id": row[3], "username": row[4], "role": row[6],
                "must_change_pw": bool(row[7]), "created_at": row[8]}
        return user, row[1]

    def delete_session(self, token):
        if not token:
            return
        with self.lock:
            self.db.execute("DELETE FROM sessions WHERE token_hash = ?",
                            (_token_hash(token),))
            self.db.commit()

    def prune(self):
        now = int(time.time())
        with self.lock:
            self.db.execute("DELETE FROM sessions WHERE expires_at < ?",
                            (now,))
            self.db.execute("DELETE FROM login_attempts WHERE ts < ?",
                            (now - ATTEMPT_RETENTION_SEC,))
            self.db.commit()

    def close(self):
        with self.lock:
            self.db.close()
