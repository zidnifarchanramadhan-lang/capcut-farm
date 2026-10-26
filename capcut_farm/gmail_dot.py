"""Gmail dot-trick mail client for github-regkit.

One real Gmail account can receive mail for an unlimited number of dot
aliases (c.ahyo@gmail.com == cahyo@gmail.com at the SMTP layer, but the
``To:`` header preserves the exact dotted address). GitHub's signup accepts
these aliases as distinct emails, so a single Gmail + App Password farms
N accounts.

This client implements the same interface as MailCxClient / LitensiClient:

    create_mailbox() -> (email, order_id)
    wait_for_code(address, timeout, log, cancel_cb, email, exclude_codes) -> str
    mark_success(order_id) / set_status(...)  (no-ops, kept for interface compat)

IMPORTANT differences vs mail.cx / Litensi:
- All aliases share ONE physical inbox, so we must filter messages by the
  EXACT ``To:`` header (case-insensitive) — we do NOT want to read a code
  addressed to a different alias.
- We mark messages ``\\Seen`` after reading so a later poll for a new alias
  does not re-return a stale code.
- GitHub codes are ``XXXX-XXXX`` with a dash, extracted the same way.
"""
from __future__ import annotations

import base64
import email
import email.header
import imaplib
import random
import re
import string
import time
from typing import Callable, Iterable, Optional

from .mail_errors import MailboxCancelled, MailboxTimeoutError


class GmailDotError(RuntimeError):
    pass


class GmailDotClient:
    """Dot-trick Gmail client backed by IMAP (imap.gmail.com:993).

    Requires an App Password (Google 2SV -> App passwords, 16 chars, no
    spaces). A regular Gmail password does NOT work for IMAP.
    """

    def __init__(self, address: str = "", app_password: str = ""):
        if not address or not app_password:
            raise GmailDotError("gmail_address / gmail_app_password not configured")
        self.address = address  # base Gmail (cahyo@gmail.com)
        self.base_local = address.split("@")[0]
        self.domain = address.split("@")[1]
        self.app_password = app_password
        self.imap_host = "imap.gmail.com"
        self.imap_port = 993
        self._last_email: str = ""
        self._local_used: set[str] = set()

    # ------------------------------------------------------------------
    # Alias generation (dot-trick)
    # ------------------------------------------------------------------
    def _random_dotted_local(self, length: int = 0) -> str:
        """Insert random dots into the base Gmail local part.

        Rules: dots allowed anywhere except leading/trailing/consecutive.
        We generate a bounded random set and avoid reusing local parts
        within one client instance.
        """
        n = len(self.base_local)
        if n < 3:
            # too short for meaningful dots — fall back to + alias, still
            # matches the dot-trick model (unique To: per alias)
            return self.base_local
        attempts = 0
        while attempts < 200:
            attempts += 1
            positions = sorted(random.sample(range(1, n), k=random.randint(1, max(1, n - 1))))
            parts = []
            prev = 0
            for p in positions:
                parts.append(self.base_local[prev:p])
                prev = p
            parts.append(self.base_local[prev:])
            candidate = ".".join(parts)
            if candidate not in self._local_used and candidate != self.base_local:
                self._local_used.add(candidate)
                return candidate
        # extremely unlikely; fall back to a bounded numeric suffix
        candidate = f"{self.base_local}{random.randint(10, 99)}"
        return candidate

    def _build_alias_email(self) -> str:
        dotted = self._random_dotted_local()
        return f"{dotted}@{self.domain}"

    # ------------------------------------------------------------------
    # Mail client interface (required by runner)
    # ------------------------------------------------------------------
    def create_mailbox(self) -> tuple[str, str]:
        """Generate a fresh dot alias. Returns (alias, alias) — order_id
        is the alias itself, kept for interface parity."""
        email_addr = self._build_alias_email()
        self._last_email = email_addr
        return email_addr, email_addr

    def get_messages(self, address: str, mark_seen: bool = True) -> list[dict]:
        """Fetch UNSEEN IMAP messages whose To header matches ``address``.

        Returns list of dicts: {from, subject, body}.
        """
        from email.header import decode_header

        out: list[dict] = []
        try:
            M = imaplib.IMAP4_SSL(self.imap_host, self.imap_port)
            M.login(self.address, self.app_password)
            M.select("INBOX")
            # Only UNSEEN messages — a code addressed to a previous alias
            # that we already consumed stays Seen and never re-matches.
            typ, data = M.search(None, "UNSEEN")
            if typ == "OK":
                nums = data[0].split()
                for num in nums[-15:]:  # cap per poll
                    typ2, msg_data = M.fetch(num, "(RFC822)")
                    if typ2 != "OK" or not msg_data or not msg_data[0]:
                        continue
                    raw = msg_data[0][1]
                    msg = email.message_from_bytes(raw)
                    to_header = msg.get("To", "")
                    if not self._to_matches(to_header, address):
                        continue
                    if mark_seen:
                        try:
                            M.store(num, "+FLAGS", "\\Seen")
                        except Exception:
                            pass
                    out.append({
                        "from": msg.get("From", ""),
                        "subject": self._decode_header_str(msg.get("Subject", "")),
                        "body": self._body_text(msg),
                    })
            M.logout()
        except imaplib.IMAP4.error as exc:
            raise GmailDotError(f"gmail IMAP login/fetch failed: {exc}")
        except Exception as exc:
            raise GmailDotError(f"gmail IMAP error: {exc}")
        return out

    @staticmethod
    def _to_matches(to_header: str, address: str) -> bool:
        """Match the EXACT alias in To (case-insensitive), not just domain."""
        target = address.strip().lower()
        for part in to_header.split(","):
            addr = re.sub(r".*<([^>]+)>.*", r"\1", part.strip())
            if addr.strip().lower() == target:
                return True
        return False

    @staticmethod
    def _decode_header_str(raw: str) -> str:
        from email.header import decode_header, make_header

        if not raw:
            return ""
        try:
            return str(make_header(decode_header(raw)))
        except Exception:
            return raw

    @staticmethod
    def _body_text(msg) -> str:
        """Return plain-text body (or stripped HTML)."""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        return payload.decode("utf-8", "replace")
            # fallback: first text/html part
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        return re.sub(r"<[^>]+>", " ", payload.decode("utf-8", "replace"))
            return ""
        payload = msg.get_payload(decode=True)
        if not payload:
            return ""
        text = payload.decode("utf-8", "replace")
        return text

    def wait_for_code(
        self,
        address: str,
        timeout: int = 240,
        poll_interval: int = 8,
        log: Optional[Callable[[str], None]] = None,
        cancel_cb: Optional[Callable[[], bool]] = None,
        email: str = "",
        exclude_codes: Optional[Iterable[str]] = None,
    ) -> str:
        """Poll the Gmail inbox until the GitHub code addressed to ``address``
        arrives. Same semantics as the Litensi/MailCx impls.

        Note: ``address`` here is the dot alias we created. The physical
        inbox is the base Gmail; To-filtering keeps aliases isolated.
        """
        started = time.time()
        skip = {str(c).strip() for c in (exclude_codes or ()) if str(c).strip()}
        attempts = 0
        while time.time() - started < timeout:
            if cancel_cb and cancel_cb():
                raise MailboxCancelled("cancelled while waiting for mail")
            try:
                messages = self.get_messages(address)
            except GmailDotError as exc:
                if log:
                    log(f"[!] gmail poll error: {exc}")
                time.sleep(min(poll_interval, 8))
                continue
            attempts += 1
            for msg in messages:
                body = "\n".join([msg.get("subject", ""), msg.get("body", "")])
                if log:
                    from_info = str(msg.get("from", ""))[:40]
                    subj_info = str(msg.get("subject", ""))[:60]
                    try:
                        log(f"[*] gmail message from={from_info} subject={subj_info}")
                    except Exception:
                        safe_subj = subj_info.encode("ascii", errors="replace").decode("ascii")
                        try:
                            log(f"[*] gmail message from={from_info} subject={safe_subj}")
                        except Exception:
                            pass
                code = self.extract_github_code(body)
                if not code:
                    continue
                if code in skip:
                    if log:
                        log(f"[*] gmail skipped already-used code {code}")
                    continue
                return code

            elapsed = int(time.time() - started)
            if log:
                log(f"[*] gmail poll #{attempts} — no code for {address} yet ({elapsed}s/{timeout}s)")
            time.sleep(min(poll_interval, 8))
        raise MailboxTimeoutError(f"no GitHub code after {timeout}s ({attempts} polls)")

    @staticmethod
    def extract_github_code(body: str) -> str:
        """GitHub sends 8-digit codes in XXXX-XXXX format."""
        if not body:
            return ""
        # strip tags -> whitespace
        plain = re.sub(r"<[^>]+>", " ", body)
        plain = re.sub(r"\s+", " ", plain).strip()
        patterns = [
            (r"verification\s+code\s+(?:is\s+)?[:\s]*(\d{6})", False),
            (r"\b(\d{6})\s+is\s+your\s+CapCut\s+code", False),
            (r"\b(\d{6})\s+is\s+your\s+Canva\s+code", False),
            (r"Your\s+Canva\s+code\s+is\s+(\d{6})", False),
            (r"Canva\s+code[:\s]+(\d{6})", False),
            (r"(\d{4})-(\d{4})", True),
            (r"code\s*[::\s]\s*(\d{6,8})", False),
            (r">\s*(\d{6,8})\s*<", False),
            (r"\b(\d{6,8})\b", False),
        ]
        for pat, two_groups in patterns:
            m = re.search(pat, plain, re.IGNORECASE)
            if m:
                return m.group(1) + m.group(2) if two_groups else m.group(1)
        return ""

    # ------------------------------------------------------------------
    # No-op lifecycle methods (interface parity with Litensi)
    # ------------------------------------------------------------------
    def mark_success(self, order_id: str) -> dict:
        return {"status": "ok", "note": "gmail dot has no order system"}

    def set_status(self, order_id: str, status: str) -> dict:
        return self.mark_success(order_id)

    @property
    def last_order_id(self) -> str:
        return self._last_email