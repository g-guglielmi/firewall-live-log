"""Outbound email for password-reset links — Python standard library only.

Configured entirely from environment variables, so no SMTP credentials are
baked into the image. If no SMTP host is configured the mailer is simply
"unconfigured" and reset emails are not sent — the API still answers
generically, so this is never observable to a client.

Setting ``MAIL_DEBUG_DIR`` writes each message to a file in that directory
instead of talking to an SMTP server. That's for local testing/development
only — never point it at anything in production.

Header-injection safety: addresses/subject flow through ``email.message``
which encodes headers, and the auth layer already rejects addresses that
contain whitespace or control characters.
"""

import smtplib
import ssl
import sys
import threading
import time
from email.message import EmailMessage


class Mailer:
    def __init__(self, host=None, port=587, username=None, password=None,
                 sender=None, sender_name=None, security="starttls",
                 debug_dir=None, timeout=15, tls_verify=True, debug=False):
        self.host = host or None
        try:
            self.port = int(port) if port else 587
        except (TypeError, ValueError):
            self.port = 587
        self.username = username or None
        self.password = password or None
        self.sender = sender or None
        self.sender_name = sender_name or None
        self.security = (security or "starttls").lower()
        self.debug_dir = debug_dir or None
        self.timeout = timeout
        self.tls_verify = tls_verify
        self.debug = debug

    def _context(self):
        """TLS context. With verification off, the connection is still
        encrypted but the server certificate isn't validated (accepts
        expired/self-signed certs) — a deliberate, opt-in trade-off."""
        ctx = ssl.create_default_context()
        if not self.tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    @property
    def configured(self):
        """True when the mailer can deliver (real SMTP) or capture (debug)."""
        return bool(self.debug_dir or (self.host and self.sender))

    def _from_header(self):
        if self.sender_name and self.sender:
            return f"{self.sender_name} <{self.sender}>"
        return self.sender or "firewall-live-log@localhost"

    def _build(self, to, subject, body):
        msg = EmailMessage()
        msg["From"] = self._from_header()
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)
        return msg

    def send(self, to, subject, body):
        """Send one message synchronously. Returns True/False; never raises
        (a mail failure must not crash a request thread)."""
        try:
            msg = self._build(to, subject, body)
            if self.debug_dir:
                import os
                os.makedirs(self.debug_dir, exist_ok=True)
                path = os.path.join(
                    self.debug_dir,
                    f"mail-{int(time.time() * 1000)}-{os.getpid()}.eml")
                with open(path, "w", encoding="utf-8") as f:
                    f.write(msg.as_string())
                return True
            if not (self.host and self.sender):
                return False
            ctx = self._context()
            if self.security == "ssl":
                with smtplib.SMTP_SSL(self.host, self.port,
                                      timeout=self.timeout, context=ctx) as s:
                    if self.debug:
                        s.set_debuglevel(1)
                    self._auth_and_send(s, msg)
            else:
                with smtplib.SMTP(self.host, self.port,
                                  timeout=self.timeout) as s:
                    if self.debug:
                        s.set_debuglevel(1)
                    s.ehlo()
                    if self.security == "starttls":
                        s.starttls(context=ctx)
                        s.ehlo()
                    self._auth_and_send(s, msg)
            return True
        except Exception as e:                     # noqa: BLE001 (never crash)
            print(f"[mail] send to {to!r} failed: {type(e).__name__}: {e}",
                  file=sys.stderr)
            return False

    def _auth_and_send(self, s, msg):
        if self.username:
            s.login(self.username, self.password or "")
        s.send_message(msg)

    def send_async(self, to, subject, body):
        """Fire-and-forget send on a daemon thread. Used so the HTTP request
        returns immediately and SMTP latency can't be used to tell whether a
        given account exists."""
        threading.Thread(target=self.send, args=(to, subject, body),
                         daemon=True).start()


def _truthy(v):
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def from_env(env):
    """Build a Mailer from an ``env(name, default=None)`` accessor."""
    return Mailer(
        host=env("SMTP_HOST"),
        port=env("SMTP_PORT", "587"),
        username=env("SMTP_USERNAME"),
        password=env("SMTP_PASSWORD"),
        sender=env("SMTP_FROM"),
        sender_name=env("SMTP_FROM_NAME"),
        security=env("SMTP_SECURITY", "starttls"),
        debug_dir=env("MAIL_DEBUG_DIR"),
        # Verification on by default; only off when explicitly disabled.
        tls_verify=not _truthy(env("SMTP_TLS_INSECURE", "false")),
        debug=_truthy(env("SMTP_DEBUG", "false")))


def reset_email_body(username, url, ttl_minutes):
    return (
        f"Hello {username},\n\n"
        f"A password reset was requested for your firewall-live-log "
        f"account.\n"
        f"Open this link to choose a new password "
        f"(valid for {ttl_minutes} minutes):\n\n"
        f"    {url}\n\n"
        f"If you didn't request this, you can ignore this email — your "
        f"password stays unchanged.\n")
