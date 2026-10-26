"""Your Mail / Temp Mail REST API client.

Universal temporary email API client for CapCut automation.
Endpoints:
  - GET  /api/domains
  - POST /api/new-address?domain=...&custom=...
  - GET  /api/messages?address=... (Header: X-Mailbox-Token)
  - GET  /api/message/:id?address=... (Header: X-Mailbox-Token)
  - DELETE /api/address?address=... (Header: X-Mailbox-Token)
"""
from __future__ import annotations

import os
import re
import time
from typing import Callable, Iterable, Optional

import requests

from .mail_errors import MailboxCancelled, MailboxTimeoutError
from .profiles import extract_github_code

PRIMARY_API_BASE = os.environ.get("TEMPMAIL_API_URL") or "https://your-api-temp-mail.com/api"


class YourMailError(RuntimeError):
    pass


class YourMailClient:
    """Temporary email client backed by Your Mail / Temp Mail REST API."""

    def __init__(self, custom_prefix: str = "", domain: str = "", api_base: str = ""):
        self.custom_prefix = (custom_prefix or "").strip()
        self.domain = (domain or "").strip()
        self.api_base = (api_base or "").strip().rstrip("/") or PRIMARY_API_BASE
        self.session = requests.Session()
        self._tokens: dict[str, str] = {}
        self._last_email: str = ""

    def get_domains(self) -> list[str]:
        """Fetch list of supported domains from /api/domains."""
        try:
            resp = self.session.get(f"{self.api_base}/domains", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict) and data.get("success"):
                    return data.get("domains", [])
                if isinstance(data, list):
                    return data
        except Exception:
            pass
        return []

    def create_mailbox(self, domain: str = "") -> tuple[str, str]:
        """Create a new temporary email address.

        Returns (email, order_id) where order_id contains 'email|token'.
        """
        target_domain = (domain or self.domain or "").strip()
        params = {}
        if target_domain and target_domain.lower() != "auto":
            params["domain"] = target_domain
        if self.custom_prefix:
            params["custom"] = self.custom_prefix

        data = None
        last_exc = None

        url = f"{self.api_base}/new-address"
        try:
            resp = self.session.post(
                url,
                params=params,
                headers={"Accept": "application/json"},
                timeout=15,
            )
            if resp.status_code == 429:
                raise YourMailError("Your Mail rate limit (429) — terlalu banyak permintaan, tunggu sebentar")
            data = resp.json()
        except requests.RequestException as exc:
            last_exc = exc
        except Exception as exc:
            last_exc = exc

        if not data or not isinstance(data, dict) or not data.get("success"):
            raise YourMailError(f"Gagal membuat mailbox Your Mail: {data or last_exc}")

        address = str(data.get("address", "")).strip().lower()
        token = str(data.get("token", "")).strip()
        if not address or "@" not in address:
            raise YourMailError(f"Alamat email Your Mail tidak valid: {address}")

        self._tokens[address] = token
        self._last_email = address
        order_id = f"{address}|{token}"
        return address, order_id

    def get_messages(self, address: str, token: str) -> list[dict]:
        """Fetch message list from /api/messages?address=... with X-Mailbox-Token header."""
        url = f"{self.api_base}/messages"
        params = {"address": address}
        headers = {
            "Accept": "application/json",
            "X-Mailbox-Token": token,
        }

        try:
            resp = self.session.get(url, params=params, headers=headers, timeout=15)
            if resp.status_code == 429:
                raise YourMailError("Your Mail rate limit (429) — mohon perlambat polling kotak masuk")
            data = resp.json()
            if isinstance(data, dict) and data.get("success"):
                msgs = data.get("messages", [])
                if isinstance(msgs, list):
                    return msgs
            return []
        except requests.RequestException as exc:
            raise YourMailError(f"Kesalahan jaringan Your Mail saat mengambil pesan: {exc}")

    def get_message_detail(self, message_id: str, address: str = "", token: str = "") -> dict:
        """Fetch full message body from /api/message/:id with X-Mailbox-Token header."""
        url = f"{self.api_base}/message/{message_id}"
        params = {}
        if address:
            params["address"] = address
        headers = {"Accept": "application/json"}
        if token:
            headers["X-Mailbox-Token"] = token

        try:
            resp = self.session.get(url, params=params, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict) and data.get("success"):
                    return data.get("message", {})
        except Exception:
            pass
        return {}

    def wait_for_code(
        self,
        order_id: str,
        timeout: int = 240,
        poll_interval: int = 5,
        log: Optional[Callable[[str], None]] = None,
        cancel_cb: Optional[Callable[[], bool]] = None,
        email: str = "",
        exclude_codes: Optional[Iterable[str]] = None,
    ) -> str:
        """Poll the Your Mail inbox until TikTok/CapCut verification code arrives."""
        started = time.time()
        skip = {str(c).strip() for c in (exclude_codes or ()) if str(c).strip()}

        # Unpack address and token
        if "|" in str(order_id):
            address, token = order_id.split("|", 1)
        else:
            address = email or order_id
            token = self._tokens.get(address, "")

        if not address:
            raise YourMailError("wait_for_code dipanggil dengan alamat kosong")

        if log:
            log(f"[*] menunggu kode OTP di {address} (Your Mail / Temp Mail, timeout={timeout}s)...")

        poll_cadence = max(4, poll_interval)

        while time.time() - started < timeout:
            if cancel_cb and cancel_cb():
                raise MailboxCancelled("dibatalkan saat menunggu email masuk")

            try:
                messages = self.get_messages(address, token)
            except YourMailError as exc:
                if "429" in str(exc):
                    if log:
                        log("[i] Your Mail rate limit terdeteksi, jeda 6s sebelum retry...")
                    time.sleep(6)
                    continue
                if log:
                    log(f"[i] Your Mail poll transient error: {exc} — mencoba lagi...")
                time.sleep(3)
                continue

            for msg in messages:
                subject = msg.get("subject", "") or ""
                snippet = msg.get("snippet", "") or ""
                combined = f"{subject} {snippet}"

                # OTP code pattern: 6 digits (CapCut / TikTok)
                code = None
                m6 = re.search(r"\b(\d{6})\b", combined)
                if m6:
                    code = m6.group(1)
                else:
                    m_gen = re.search(r"\b(\d{4,8})\b", combined)
                    if m_gen:
                        code = m_gen.group(1)
                    else:
                        code = extract_github_code(combined)

                if not code and msg.get("id"):
                    detail = self.get_message_detail(msg["id"], address=address, token=token)
                    body_text = detail.get("body_text", "") or ""
                    body_html = detail.get("body_html", "") or ""
                    full_text = f"{subject} {body_text} {body_html}"

                    m6 = re.search(r"\b(\d{6})\b", full_text)
                    if m6:
                        code = m6.group(1)
                    else:
                        m_gen = re.search(r"\b(\d{4,8})\b", full_text)
                        if m_gen:
                            code = m_gen.group(1)
                        else:
                            code = extract_github_code(full_text)

                if code:
                    clean_code = re.sub(r"\D", "", code)
                    if clean_code in skip:
                        continue
                    if log:
                        log(f"[+] Your Mail: kode verifikasi ditemukan: {clean_code}")
                    return clean_code

            deadline_sleep = time.time() + poll_cadence
            while time.time() < deadline_sleep:
                if cancel_cb and cancel_cb():
                    raise MailboxCancelled("dibatalkan saat menunggu email masuk")
                time.sleep(min(0.5, deadline_sleep - time.time()))

        raise MailboxTimeoutError(f"tidak ada kode OTP diterima di {address} setelah {timeout} detik")

    def mark_success(self, order_id: str) -> None:
        """Interface compatibility method."""
        pass


# Aliases for backward compatibility
ZayMailClient = YourMailClient
ZayMailError = YourMailError
