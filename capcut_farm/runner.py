"""CapCut sign-up automation driven by Camoufox (Firefox anti-detect) + Mail Providers."""
from __future__ import annotations

import collections
import hashlib
import json
import logging
import os
import random
import re
import socket
import socketserver
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit

if sys.platform == "win32":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

try:
    from camoufox.sync_api import Camoufox
except ImportError:
    Camoufox = None

import requests

from .config import Config
from .gmail_dot import GmailDotClient, GmailDotError
from .litensi import LitensiClient, LitensiError
from .mail_errors import MailboxCancelled, MailboxTimeoutError
from .mailcx import MailCxClient, MailCxError
from .profiles import (
    generate_full_name,
    generate_password,
    generate_username,
)
from .yourmail import YourMailClient, YourMailError

ROOT = Path(__file__).resolve().parent.parent
ACCOUNTS_DIR = ROOT / "accounts"
RECOVERY_DIR = ACCOUNTS_DIR / "recovery"

CAPCUT_SIGNUP_URL = "https://www.capcut.com/signup"
CAPCUT_LOGIN_URL = "https://www.capcut.com/login"


def _recovery_path(email: str) -> Path:
    key = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
    return RECOVERY_DIR / f"{key}.txt"


def _record_account(out_path: Optional[Path], line: str, log=None) -> None:
    """Atomically record or update an account line in the target accounts file."""
    if not out_path or not line:
        return
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        email = re.split(r"----|\|", line, maxsplit=1)[0].strip().lower()
        if out_path.is_file():
            content = out_path.read_text(encoding="utf-8")
            lines = content.splitlines()
            updated = False
            new_lines = []
            for existing in lines:
                existing_email = re.split(r"----|\|", existing, maxsplit=1)[0].strip().lower()
                if existing_email == email:
                    new_lines.append(line.strip())
                    updated = True
                else:
                    new_lines.append(existing)
            if updated:
                out_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
                return
        with out_path.open("a", encoding="utf-8") as f:
            f.write(line.strip() + "\n")
        if log:
            log(f"[+] account recorded to {out_path.name}: {email}")
    except Exception as exc:
        if log:
            log(f"[i] failed writing account to {out_path}: {exc}")


class SignupError(RuntimeError):
    pass


class SignupBlocked(SignupError):
    pass


class RegistrationCancelled(SignupError):
    pass


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _raise_if_cancelled(stop) -> None:
    if stop and stop():
        raise RegistrationCancelled("stop requested")


def _sleep_with_cancel(seconds: float, stop=None) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        _raise_if_cancelled(stop)
        time.sleep(min(0.25, deadline - time.time()))


def silence_playwright_noise() -> None:
    logging.getLogger("asyncio").setLevel(logging.CRITICAL)


# ---------------------------------------------------------------------------
# Proxy Helpers
# ---------------------------------------------------------------------------

def normalize_proxy_url(line: str, default_scheme: str = "http") -> Optional[str]:
    line = (line or "").strip()
    if not line or line.startswith("#"):
        return None

    if "://" in line:
        p = urlsplit(line)
        if p.hostname and (p.scheme or "").lower() in ("http", "https", "socks4", "socks5", "socks"):
            scheme = "socks5" if p.scheme.lower() in ("socks", "socks5h") else p.scheme.lower()
            auth = f"{p.username}:{p.password}@" if p.username else ""
            port = f":{p.port}" if p.port else ""
            return f"{scheme}://{auth}{p.hostname}{port}"
        return None

    if "@" in line:
        candidate = f"{default_scheme}://{line}"
        p = urlsplit(candidate)
        if p.hostname:
            return candidate
        return None

    parts = [part.strip() for part in line.split(":") if part.strip()]
    if len(parts) == 2:
        host, port = parts
        if port.isdigit() and 1 <= int(port) <= 65535:
            return f"{default_scheme}://{host}:{port}"
    elif len(parts) == 4:
        p1_is_port = parts[1].isdigit() and 1 <= int(parts[1]) <= 65535
        p3_is_port = parts[3].isdigit() and 1 <= int(parts[3]) <= 65535
        if p1_is_port and not p3_is_port:
            host, port, user, pwd = parts
            return f"{default_scheme}://{user}:{pwd}@{host}:{port}"
        elif p3_is_port and not p1_is_port:
            user, pwd, host, port = parts
            return f"{default_scheme}://{user}:{pwd}@{host}:{port}"
        elif p1_is_port and p3_is_port:
            if "." in parts[0] and "." not in parts[2]:
                host, port, user, pwd = parts
                return f"{default_scheme}://{user}:{pwd}@{host}:{port}"
            else:
                user, pwd, host, port = parts
                return f"{default_scheme}://{user}:{pwd}@{host}:{port}"
        else:
            if "." in parts[2]:
                user, pwd, host, port = parts
                return f"{default_scheme}://{user}:{pwd}@{host}:{port}"
            elif "." in parts[0]:
                host, port, user, pwd = parts
                return f"{default_scheme}://{user}:{pwd}@{host}:{port}"

    return None


def _parse_proxy(url: str) -> Optional[dict]:
    url = (url or "").strip()
    if not url:
        return None
    normalized = normalize_proxy_url(url)
    if normalized:
        url = normalized
    p = urlsplit(url)
    if not p.hostname:
        raise SignupError(f"invalid proxy url: {url}")
    scheme = (p.scheme or "http").lower()
    if scheme in ("socks", "socks5h"):
        scheme = "socks5"
    if scheme not in ("http", "https", "socks4", "socks5"):
        raise SignupError(f"unsupported proxy scheme: {p.scheme}:// (use http/socks5)")
    port = p.port or (1080 if scheme.startswith("socks") else (443 if scheme == "https" else 80))
    proxy = {"server": f"{scheme}://{p.hostname}:{port}"}
    if p.username:
        proxy["username"] = p.username
        proxy["password"] = p.password or ""
    return proxy


def load_proxy_pool(name: str) -> list[str]:
    path = ROOT / name.strip()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out: list[str] = []
    for line in lines:
        norm = normalize_proxy_url(line)
        if norm:
            out.append(norm)
    return out


def _pick_proxy_url(cfg: Config, log=None) -> str:
    name = (getattr(cfg, "proxy_file", "") or "").strip()
    if name:
        pool = load_proxy_pool(name)
        if pool:
            return random.choice(pool)
        if log:
            log(f"[!] proxy file {name!r} missing/empty — falling back to single proxy URL")
    return (cfg.proxy or "").strip()


def _proxy_is_socks(proxy: Optional[dict]) -> bool:
    return bool(proxy) and str(proxy.get("server", "")).startswith("socks")


def _socks_exit_ip(url: str, timeout: int = 12) -> str:
    import requests as _requests

    p = urlsplit(url.strip())
    scheme = "socks5h" if (p.scheme or "socks").lower().startswith("socks") else (p.scheme or "http")
    auth = f"{p.username}:{p.password}@" if p.username else ""
    port = p.port or 1080
    proxies = {"http": f"{scheme}://{auth}{p.hostname}:{port}",
               "https": f"{scheme}://{auth}{p.hostname}:{port}"}
    last_exc: Exception | None = None
    for attempt in range(2):
        for check_url in ("https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.co/ip"):
            try:
                resp = _requests.get(check_url, proxies=proxies, timeout=20)
                ip = (resp.text or "").strip()
                if resp.ok and ip:
                    return ip
            except Exception as exc:
                last_exc = exc
        if attempt == 0:
            time.sleep(3)
    raise SignupError(f"proxy exit-IP lookup failed: {last_exc}")


_sticky_suffix: Optional[str] = None
_last_exit_ip: Optional[str] = None


def _ensure_sticky_proxy(url: str, log=None) -> str:
    p = urlsplit(url.strip())
    port = p.port or 0
    if log:
        safe = re.sub(r"(//[^:]+:)[^@]+@", r"\1***@", url.strip())
        log(f"[*] proxy selected: {safe} (port {port})")
    if port in (823, 824):
        global _sticky_suffix
        if _sticky_suffix is None:
            import secrets as _secrets
            _sticky_suffix = str(10000 + int(_secrets.token_hex(4), 16) % 10001)
            if log:
                log(f"[*] sticky proxy port: {_sticky_suffix} (DataImpulse sticky)")
        scheme = (p.scheme or "socks5").lower()
        if scheme in ("socks", "socks5h"):
            scheme = "socks5"
        auth = f"{p.username}:{p.password}@" if p.username else ""
        return f"{scheme}://{auth}{p.hostname}:{_sticky_suffix}"
    return url.strip()


_UPSTREAM: dict = {}


class _AuthBridgeHandler(socketserver.BaseRequestHandler):
    def _relay(self, src: socket.socket, dst: socket.socket, timeout: float = 180.0) -> None:
        src.settimeout(timeout)
        dst.settimeout(timeout)

        def pump(a: socket.socket, b: socket.socket) -> None:
            try:
                while True:
                    data = a.recv(65536)
                    if not data:
                        break
                    b.sendall(data)
            except OSError:
                pass
            finally:
                for sock in (a, b):
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        t1 = threading.Thread(target=pump, args=(src, dst), daemon=True)
        t2 = threading.Thread(target=pump, args=(dst, src), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    def _connect_upstream(self) -> socket.socket:
        s = socket.create_connection((_UPSTREAM["host"], _UPSTREAM["port"]), timeout=20)
        if _UPSTREAM["socks"]:
            s.sendall(b"\x05\x01\x02")
            resp = s.recv(2)
            if len(resp) < 2 or resp[0] != 5:
                raise OSError("socks5: bad greeting")
            if resp[1] == 0x02:
                user = _UPSTREAM["user"].encode()
                pwd = _UPSTREAM["pass"].encode()
                s.sendall(bytes([1, len(user)]) + user + bytes([len(pwd)]) + pwd)
                resp = s.recv(2)
                if len(resp) < 2 or resp[1] != 0:
                    raise OSError("socks5: auth rejected")
            elif resp[1] != 0x00:
                raise OSError("socks5: no acceptable auth method")
        return s

    def _socks5_connect_remote(self, s: socket.socket, host: str, port: int) -> None:
        h = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + port.to_bytes(2, "big"))
        resp = s.recv(10)
        if len(resp) < 2 or resp[1] != 0:
            raise OSError(f"socks5: connect failed code={resp[1] if len(resp) > 1 else '?'}")

    def _inject_auth_header(self, data: bytes) -> bytes:
        if not _UPSTREAM.get("user"):
            return data
        import base64
        token = base64.b64encode(f"{_UPSTREAM['user']}:{_UPSTREAM['pass']}".encode()).decode()
        head, sep, rest = data.partition(b"\r\n\r\n")
        if not sep:
            return data
        lines = head.split(b"\r\n")
        out = [lines[0]]
        for ln in lines[1:]:
            if ln.lower().startswith(b"proxy-authorization:"):
                continue
            out.append(ln)
        out.append(f"Proxy-Authorization: Basic {token}".encode())
        return b"\r\n".join(out) + b"\r\n\r\n" + rest

    def handle(self) -> None:
        try:
            self.request.settimeout(20)
            first = self.request.recv(65536)
            if not first:
                return
            if first[:7] == b"CONNECT":
                line = first.split(b"\r\n", 1)[0]
                hostport = line.split()[1].decode()
                host, _, port_s = hostport.rpartition(":")
                port = int(port_s or "443")
                upstream = self._connect_upstream()
                if _UPSTREAM["socks"]:
                    self._socks5_connect_remote(upstream, host, port)
                    self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                else:
                    authed = self._inject_auth_header(first)
                    upstream.sendall(authed)
                    reply = self._wait_http_connect_reply(upstream)
                    self.request.sendall(reply)
                self._relay(self.request, upstream)
            else:
                upstream = self._connect_upstream()
                upstream.sendall(self._inject_auth_header(first))
                self._relay(self.request, upstream)
        except OSError:
            pass
        finally:
            try:
                self.request.close()
            except OSError:
                pass

    @staticmethod
    def _wait_http_connect_reply(upstream: socket.socket, timeout: float = 20.0) -> bytes:
        upstream.settimeout(timeout)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 8192:
            chunk = upstream.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf or b"HTTP/1.1 502 Bad Gateway\r\n\r\n"


class LocalAuthProxyBridge:
    def __init__(self, proxy_url: str):
        p = urlsplit(proxy_url.strip())
        scheme = (p.scheme or "http").lower()
        if scheme in ("socks", "socks5", "socks5h"):
            scheme = "socks5"
        if not p.hostname:
            raise SignupError(f"invalid proxy url for bridge: {proxy_url}")
        self._upstream = {
            "host": p.hostname,
            "port": p.port or (1080 if scheme == "socks5" else 8080),
            "user": p.username or "",
            "pass": p.password or "",
            "socks": scheme == "socks5",
        }
        self._server: Optional[socketserver.ThreadingTCPServer] = None
        self.port: Optional[int] = None

    def start(self) -> int:
        global _UPSTREAM
        _UPSTREAM = self._upstream
        for attempt in range(20):
            candidate = 20000 + (os.getpid() % 10000) + attempt * 7
            try:
                self._server = socketserver.ThreadingTCPServer(
                    ("127.0.0.1", candidate), _AuthBridgeHandler
                )
                self._server.daemon_threads = True
                self.port = candidate
                threading.Thread(target=self._server.serve_forever, daemon=True).start()
                return candidate
            except OSError:
                continue
        raise SignupError("local auth proxy bridge: no free port found")

    def stop(self) -> None:
        if self._server:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None

    def browser_proxy(self) -> dict:
        return {"server": f"http://127.0.0.1:{self.port}"}


_bridge: Optional[LocalAuthProxyBridge] = None


def _stop_proxy_bridge() -> None:
    global _bridge
    if _bridge is not None:
        _bridge.stop()
        _bridge = None


def _rotate_sticky_proxy() -> None:
    global _sticky_suffix, _last_exit_ip
    _stop_proxy_bridge()
    _sticky_suffix = None
    _last_exit_ip = None


def _disable_blocked_proxy(log) -> None:
    try:
        import urllib.request
        req = urllib.request.Request(
            "http://127.0.0.1:8100/disable",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=5)
        data = json.loads(resp.read())
        if data.get("ok"):
            log(f"[!] permanently disabled proxy: {data.get('disabled')}")
    except Exception:
        pass


def _proxy_needs_bridge(proxy: Optional[dict]) -> bool:
    return bool(proxy) and str(proxy.get("server", "")).startswith("socks") and proxy.get("username")


def _browser_ctx_options(cfg: Config, log=None) -> dict:
    opts = {
        "headless": cfg.headless,
        "humanize": True,
        "geoip": True,
        "os": "windows",
    }
    raw_proxy = _pick_proxy_url(cfg, log=log)
    proxy_url = _ensure_sticky_proxy(raw_proxy, log=log) if raw_proxy else ""
    proxy = _parse_proxy(proxy_url) if proxy_url else None
    if proxy:
        if _proxy_needs_bridge(proxy):
            global _bridge
            if _bridge is None:
                _bridge = LocalAuthProxyBridge(proxy_url)
                _bridge.start()
                if log:
                    log(f"[*] local auth bridge 127.0.0.1:{_bridge.port} -> {proxy['server']}")
            opts["proxy"] = _bridge.browser_proxy()
        else:
            opts["proxy"] = proxy
        if _proxy_is_socks(proxy):
            try:
                exit_ip = _socks_exit_ip(proxy_url)
                opts["geoip"] = exit_ip
                global _last_exit_ip
                _last_exit_ip = exit_ip
                if log:
                    log(f"[*] socks proxy exit IP: {exit_ip} (sticky)")
            except Exception as exc:
                opts["geoip"] = False
                _last_exit_ip = None
    return opts


def _context_and_page(browser):
    if hasattr(browser, "cookies"):
        context = browser
        page = context.pages[0] if context.pages else context.new_page()
    else:
        context = browser.new_context(
            locale="en-US",
            viewport={"width": 1280, "height": 800},
        )
        page = context.new_page()
    return context, page


def _page_text(page) -> str:
    try:
        return page.locator("body").inner_text(timeout=2000)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# TikTok Registration & CapCut TikTok SSO Bridge
# ---------------------------------------------------------------------------

TIKTOK_SIGNUP_URL = "https://www.tiktok.com/signup/phone-or-email/email"


def _wait_for_captcha_if_any(page, log, stop=None, timeout: int = 60) -> None:
    """Detect ByteDance captcha/puzzle and wait for user to solve or auto-pass."""
    _raise_if_cancelled(stop)
    captcha_loc = page.locator(
        ".secsdk-captcha-drag-icon, #captcha-verify-image, .captcha_verify_container, "
        "[class*='captcha_verify'], .verify-bar-close, .captcha-disable-click, "
        "div[class*='captcha'] img, [id*='captcha']"
    ).first
    try:
        if captcha_loc.is_visible(timeout=2500):
            log("[!] [CAPTCHA ] Terdeteksi puzzle captcha TikTok! Silakan geser puzzle di layar browser...")
            start_time = time.time()
            while time.time() - start_time < timeout:
                _raise_if_cancelled(stop)
                try:
                    if not captcha_loc.is_visible(timeout=1000):
                        log("[+] [CAPTCHA ] Puzzle captcha berhasil diselesaikan!")
                        _sleep_with_cancel(1.5, stop)
                        break
                except Exception:
                    break
                _sleep_with_cancel(1.0, stop)
    except Exception:
        pass


def _ensure_tiktok_email_tab(page, log, stop=None) -> None:
    """Ensure TikTok signup is on the Email form, not Phone form."""
    _raise_if_cancelled(stop)

    # Check if email input is already visible
    email_inp = page.locator(
        "input[type='email'], input[name='email'], input[placeholder*='Email'], input[placeholder*='email']"
    ).first
    if email_inp.is_visible(timeout=3000):
        return

    log("[*] [TIKTOK   ] Terdeteksi pendaftaran nomor telepon, beralih ke tab email...")
    switched = False

    # Look for switch button: "Sign up with email" / "Daftar dengan email"
    for _ in range(5):
        _raise_if_cancelled(stop)
        try:
            switch_btn = page.locator(
                "a:has-text('Sign up with email'), a:has-text('Daftar dengan email'), "
                "button:has-text('Sign up with email'), button:has-text('Daftar dengan email'), "
                "span:has-text('Sign up with email'), span:has-text('Daftar dengan email'), "
                "[data-e2e='switch-to-email'], a[href*='phone-or-email/email']"
            ).first
            if switch_btn.is_visible(timeout=2000):
                switch_btn.click(force=True)
                switched = True
                _sleep_with_cancel(1.5, stop)
                break
        except Exception:
            pass
        _sleep_with_cancel(0.8, stop)

    if not switched:
        # Fallback via JavaScript click
        try:
            page.evaluate("""() => {
                const links = Array.from(document.querySelectorAll('a, button, span, div, p'));
                const target = links.find(el => {
                    const t = (el.innerText || el.textContent || '').trim().toLowerCase();
                    return t === 'sign up with email' || t === 'daftar dengan email';
                });
                if (target) {
                    target.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
                    target.click();
                }
            }""")
            _sleep_with_cancel(1.5, stop)
        except Exception:
            pass

    email_inp.wait_for(state="visible", timeout=15000)
    log("[+] [TIKTOK   ] Berhasil masuk ke formulir pendaftaran email!")


def _fill_tiktok_birthday(page, log, stop=None) -> None:
    """Select Month, Day, Year (Januari 15, 1998 -> 18+ years old) on TikTok."""
    _raise_if_cancelled(stop)
    log("[*] [TIKTOK   ] Mengisi tanggal lahir (Januari 15, 1998)...")

    # Native <select> check first
    try:
        selects = page.locator("select").all()
        if len(selects) >= 3:
            selects[0].select_option(index=1)
            _sleep_with_cancel(0.3, stop)
            selects[1].select_option(index=15)
            _sleep_with_cancel(0.3, stop)
            try:
                selects[2].select_option(value="1998")
            except Exception:
                selects[2].select_option(index=25)
            _sleep_with_cancel(0.5, stop)
            return
    except Exception:
        pass

    # TikTok custom dropdowns
    # 1. Month
    try:
        m_trigger = page.locator(
            "[id*='Month'][role='combobox'], [id='Month'], [aria-label*='Month']"
        ).first
        if not m_trigger.is_visible(timeout=1500):
            combos = page.locator("[role='combobox'], [aria-haspopup='listbox']").all()
            if combos:
                m_trigger = combos[0]
        m_trigger.click(force=True)
        _sleep_with_cancel(0.5, stop)

        # Click January
        m_opt = page.locator("[id*='Month-options-item-0'], [id*='Month-options-item']:has-text('Jan'), [role='option']:has-text('Jan')").first
        if m_opt.is_visible(timeout=2000):
            m_opt.click(force=True)
        _sleep_with_cancel(0.5, stop)
    except Exception as exc:
        log(f"[i] [TIKTOK   ] month selector: {exc}")

    # 2. Day
    try:
        d_trigger = page.locator(
            "[id*='Day'][role='combobox'], [id='Day'], [aria-label*='Day']"
        ).first
        if not d_trigger.is_visible(timeout=1500):
            combos = page.locator("[role='combobox'], [aria-haspopup='listbox']").all()
            if len(combos) >= 2:
                d_trigger = combos[1]
        d_trigger.click(force=True)
        _sleep_with_cancel(0.5, stop)

        # Click Day 15 (item index 14)
        d_opt = page.locator("[id='Day-options-item-14'], [id*='Day-options-item']:has-text('15')").first
        if d_opt.is_visible(timeout=2000):
            d_opt.click(force=True)
        else:
            d_fallback = page.locator("[id*='Day-options-item']").nth(14)
            if d_fallback.is_visible(timeout=1000):
                d_fallback.click(force=True)
        _sleep_with_cancel(0.5, stop)
    except Exception as exc:
        log(f"[i] [TIKTOK   ] day selector: {exc}")

    # 3. Year
    try:
        y_trigger = page.locator(
            "[id*='Year'][role='combobox'], [id='Year'], [aria-label*='Year']"
        ).first
        if not y_trigger.is_visible(timeout=1500):
            combos = page.locator("[role='combobox'], [aria-haspopup='listbox']").all()
            if len(combos) >= 3:
                y_trigger = combos[2]
        y_trigger.click(force=True)
        _sleep_with_cancel(0.5, stop)

        # Find Year 1998 or 1999 and scroll into view & click
        selected_year = page.evaluate("""() => {
            const opts = Array.from(document.querySelectorAll('[id*="Year-options-item"], [role="option"]'));
            const target = opts.find(el => {
                const t = (el.innerText || el.textContent || '').trim();
                return t === '1998' || t === '1999' || t === '2000' || t === '1997';
            });
            if (target) {
                target.scrollIntoView({ behavior: 'instant', block: 'center' });
                target.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
                target.click();
                return target.innerText.trim();
            }
            return null;
        }""")
        if selected_year:
            log(f"[*] [TIKTOK   ] Tahun lahir terpilih: {selected_year}")
        else:
            y_opt = page.locator("[id*='Year-options-item']:has-text('1998'), [id*='Year-options-item']:has-text('1999')").first
            if y_opt.is_visible(timeout=2000):
                y_opt.click(force=True)
        _sleep_with_cancel(0.5, stop)
    except Exception as exc:
        log(f"[i] [TIKTOK   ] year selector: {exc}")


def _register_tiktok_account(
    page,
    mail,
    email: str,
    password: str,
    order_id: str,
    cfg: Config,
    log,
    stop=None,
    attempts: int = 3,
) -> None:
    """Register account on TikTok with given email and password."""
    _raise_if_cancelled(stop)
    log("[>] [TIKTOK 1/4] Membuka formulir pendaftaran TikTok...")

    for attempt in range(1, attempts + 1):
        _raise_if_cancelled(stop)
        try:
            page.goto(TIKTOK_SIGNUP_URL, wait_until="domcontentloaded", timeout=45000)
            _sleep_with_cancel(2.5, stop)
            break
        except Exception as exc:
            if attempt == attempts:
                raise SignupError(f"Gagal membuka TikTok signup: {exc}")
            log(f"[!] Gagal membuka TikTok ({exc}), mencoba ulang ({attempt}/{attempts})...")
            _sleep_with_cancel(3.0, stop)

    # Dismiss cookies / tracking banners on TikTok
    try:
        cookie_btn = page.locator(
            "button:has-text('Accept all'), button:has-text('Terima semua'), "
            "button:has-text('Allow all cookies'), button:has-text('Accept'), "
            "button:has-text('Setuju'), [aria-label='Close']"
        ).first
        if cookie_btn.is_visible(timeout=2500):
            cookie_btn.click()
            log("[*] [TIKTOK   ] Cookie banner ditutup")
            _sleep_with_cancel(0.5, stop)
    except Exception:
        pass

    # Ensure on email tab (switch if phone tab is displayed)
    _ensure_tiktok_email_tab(page, log, stop=stop)

    # 1. Fill birthday (Jan 15, 1998)
    _fill_tiktok_birthday(page, log, stop=stop)

    # 2. Fill email using fill()
    log(f"[>] [TIKTOK 2/4] Mengisi email pendaftaran: {email}")
    em_inp = page.locator(
        "input[type='email'], input[name='email'], input[placeholder*='Email'], input[placeholder*='email']"
    ).first
    em_inp.wait_for(state="visible", timeout=15000)
    em_inp.click()
    em_inp.fill(email)
    _sleep_with_cancel(0.5, stop)

    # Verify email input
    val = em_inp.input_value().strip()
    if val != email:
        em_inp.fill("")
        em_inp.fill(email)
        _sleep_with_cancel(0.5, stop)

    # Dismiss any floating email autocomplete dropdowns (e.g. @gmail.com suggestion)
    try:
        page.keyboard.press("Escape")
        page.evaluate("() => { const d = document.querySelector('[class*=\"DivEmailContainer\"], [class*=\"LiListItem\"]'); if (d) d.remove(); }")
    except Exception:
        pass
    _sleep_with_cancel(0.3, stop)

    # 3. Fill password using fill()
    log(f"[*] [TIKTOK   ] Mengisi password pendaftaran ({len(password)} karakter)...")
    pwd_inp = page.locator(
        "input[type='password'], input[placeholder*='Password'], input[placeholder*='sandi'], input[placeholder*='Kata sandi']"
    ).first
    pwd_inp.wait_for(state="visible", timeout=10000)
    try:
        pwd_inp.click(timeout=3000)
    except Exception:
        pwd_inp.click(timeout=3000, force=True)
    pwd_inp.fill(password)
    _sleep_with_cancel(0.5, stop)

    # Blur password input to trigger TikTok form validation
    try:
        page.locator("body").click(position={"x": 5, "y": 5})
        _sleep_with_cancel(0.8, stop)
    except Exception:
        pass

    # 4. Click 'Send code' / 'Kirim kode'
    log("[*] [TIKTOK   ] Mengklik tombol Kirim Kode Verifikasi...")
    send_btn = page.locator(
        "button[data-e2e='send-code-button'], button:has-text('Send code'), button:has-text('Kirim kode'), button:has-text('Send Code')"
    ).first
    send_btn.wait_for(state="visible", timeout=10000)

    # Wait for send_btn to become enabled if currently disabled
    enabled_wait = time.time() + 8
    while time.time() < enabled_wait:
        _raise_if_cancelled(stop)
        if send_btn.is_enabled():
            break
        _sleep_with_cancel(0.5, stop)

    try:
        send_btn.click(timeout=3000)
    except Exception:
        send_btn.click(timeout=3000, force=True)
    _sleep_with_cancel(2.0, stop)

    # Wait for puzzle/captcha if presented
    _wait_for_captcha_if_any(page, log, stop=stop)

    # 5. Wait for OTP from mail provider
    log(f"[~] [TIKTOK 3/4] Menunggu kode verifikasi TikTok masuk di {email}...")
    raw_code = mail.wait_for_code(
        order_id,
        timeout=cfg.otp_timeout_sec,
        log=log,
        cancel_cb=stop,
        email=email,
    )
    if not raw_code:
        raise SignupError("Kode OTP TikTok tidak ditemukan di mailbox")

    code = re.sub(r"\D", "", raw_code)[:6]
    log(f"[+] [TIKTOK   ] Kode OTP TikTok diterima: {code}")

    # 6. Enter OTP code
    otp_inp = page.locator(
        "input[placeholder*='code'], input[placeholder*='kode'], input[maxlength='6'], "
        "input[autocomplete='one-time-code'], [data-e2e='code-input']"
    ).first
    otp_inp.wait_for(state="visible", timeout=10000)
    otp_inp.click()
    otp_inp.fill(code)
    _sleep_with_cancel(1.0, stop)

    # 7. Click Next / Sign up
    log("[*] [TIKTOK   ] Mengirim konfirmasi pendaftaran...")
    sub_btn = page.locator(
        "button[type='submit'], button:has-text('Next'), button:has-text('Berikutnya'), "
        "button:has-text('Sign up'), button:has-text('Daftar')"
    ).first
    if sub_btn.is_visible(timeout=3000):
        sub_btn.click()
        _sleep_with_cancel(3.0, stop)

    _wait_for_captcha_if_any(page, log, stop=stop)

    # 8. Check if username prompt appears
    try:
        user_inp = page.locator("input[placeholder*='username'], input[placeholder*='Nama pengguna']").first
        if user_inp.is_visible(timeout=4000):
            uname = generate_username()
            log(f"[*] [TIKTOK   ] Mengisi username TikTok: {uname}")
            user_inp.fill(uname)
            _sleep_with_cancel(0.5, stop)
            sign_btn = page.locator("button:has-text('Sign up'), button:has-text('Daftar'), button:has-text('Done')").first
            if sign_btn.is_visible(timeout=2000):
                sign_btn.click()
                _sleep_with_cancel(2.0, stop)
    except Exception:
        pass

    log("[+] [TIKTOK 4/4] Akun TikTok berhasil dibuat & sesi login aktif!")
    _sleep_with_cancel(2.0, stop)


def _login_capcut_via_tiktok(context, page, log, stop=None) -> None:
    """Connect to CapCut and authorize login using the active TikTok session."""
    _raise_if_cancelled(stop)
    log("[>] [CAPCUT SSO] Membuka halaman login CapCut...")
    page.goto(CAPCUT_SIGNUP_URL, wait_until="domcontentloaded", timeout=45000)
    _sleep_with_cancel(2.5, stop)

    # Dismiss cookies banner
    try:
        cookie_btn = page.locator(
            "button:has-text('Accept all cookies'), button:has-text('Terima semua cookie'), "
            "button:has-text('Accept'), button:has-text('Terima'), button:has-text('Agree'), "
            "[aria-label='Close'], button.agree-btn"
        ).first
        if cookie_btn.is_visible(timeout=2500):
            cookie_btn.click()
            _sleep_with_cancel(0.5, stop)
    except Exception:
        pass

    # Click 'Lanjutkan dengan TikTok' / 'Continue with TikTok'
    log("[>] [CAPCUT SSO] Mengklik tombol 'Lanjutkan dengan TikTok'...")
    tt_btn = page.locator(
        "[class*='lv_third_part_sign_in']:has-text('TikTok'), "
        "span.lv_third_part_sign_in-label:has-text('TikTok'), "
        "button:has-text('TikTok'), div[role='button']:has-text('TikTok'), "
        "[aria-label*='TikTok']"
    ).first
    tt_btn.wait_for(state="visible", timeout=15000)

    # Listen for popup page if TikTok OAuth opens in a new tab/window
    opened_popups = []
    def _on_page(p):
        opened_popups.append(p)
    context.on("page", _on_page)

    tt_btn.click()
    _sleep_with_cancel(3.0, stop)

    # Determine which page is the authorization page
    auth_page = page
    for _ in range(12):
        _raise_if_cancelled(stop)
        if opened_popups:
            auth_page = opened_popups[-1]
            break
        if "tiktok.com" in page.url.lower():
            auth_page = page
            break
        _sleep_with_cancel(1.0, stop)

    # Wait for Authorize button on TikTok authorization page
    log("[*] [CAPCUT SSO] Menyetujui otorisasi TikTok ke akun CapCut...")
    auth_deadline = time.time() + 25
    while time.time() < auth_deadline:
        _raise_if_cancelled(stop)
        try:
            auth_btn = auth_page.locator(
                "button:has-text('Authorize'), button:has-text('Otorisasikan'), "
                "button:has-text('Continue'), button:has-text('Lanjutkan'), "
                "[data-e2e='auth-button'], div[role='button']:has-text('Authorize')"
            ).first
            if auth_btn.is_visible(timeout=2000):
                auth_btn.click()
                log("[+] [CAPCUT SSO] Otorisasi TikTok berhasil dikonfirmasi!")
                _sleep_with_cancel(2.5, stop)
                break
        except Exception:
            pass
        _sleep_with_cancel(1.0, stop)

    # Wait for redirect back to CapCut
    log("[*] [CAPCUT SSO] Menunggu redirect ke dashboard CapCut...")
    redirect_deadline = time.time() + 25
    while time.time() < redirect_deadline:
        _raise_if_cancelled(stop)
        curr_url = page.url.lower()
        if "capcut.com" in curr_url and ("my-edit" in curr_url or "workspace" in curr_url or "home" in curr_url or "login" not in curr_url):
            log("[+] [CAPCUT SSO] Berhasil login ke dashboard CapCut via TikTok!")
            break
        _sleep_with_cancel(1.5, stop)


# ---------------------------------------------------------------------------
# CapCut Registration Flow
# ---------------------------------------------------------------------------

def _open_capcut_signup(page, log, stop=None, attempts: int = 3) -> None:
    """Navigate to CapCut signup page and open email signup form."""
    last_exc = None
    for attempt in range(1, attempts + 1):
        _raise_if_cancelled(stop)
        log(f"[*] opening {CAPCUT_SIGNUP_URL} (attempt {attempt}/{attempts})...")
        try:
            page.goto(CAPCUT_SIGNUP_URL, wait_until="domcontentloaded", timeout=45000)
            _sleep_with_cancel(2.0, stop)

            # Accept cookies / privacy banners if visible
            try:
                cookie_btn = page.locator(
                    "button:has-text('Accept all cookies'), button:has-text('Terima semua cookie'), "
                    "button:has-text('Accept'), button:has-text('Terima'), "
                    "button:has-text('Agree'), button:has-text('Setuju'), "
                    "[aria-label='Close'], button.agree-btn"
                ).first
                if cookie_btn.is_visible(timeout=2000):
                    cookie_btn.click()
                    log("[*] accepted cookies banner")
                    _sleep_with_cancel(0.5, stop)
            except Exception:
                pass

            # Wait for login/signup container or email input to appear
            try:
                page.wait_for_selector(
                    ".lv_third_part_sign_in_expand-wrapper, .lv-account-login-form-main-field, [class*='sign_in-container'], input[type='email']",
                    timeout=20000
                )
            except Exception as e:
                log(f"[i] wait_for_selector info: {e}")

            # Click 'Lanjutkan dengan alamat email' / 'Continue with email'
            inp = page.locator("input[type='email'], input[name='username']").first
            if not inp.is_visible(timeout=1500):
                clicked_info = page.evaluate("""() => {
                    const newBtn = document.querySelector('.lv_third_part_sign_in_expand_new-button, [class*="expand_new-button"]');
                    if (newBtn) {
                        newBtn.click();
                        return { clicked: true, text: newBtn.innerText, tag: newBtn.tagName };
                    }
                    const els = Array.from(document.querySelectorAll('.lv_third_part_sign_in_expand-wrapper *, .lv_third_part_sign_in_expand-label, .lv-account-login-form-main-field *, [class*="sign_in"] *, [class*="third_part"] *, button, div, span'));
                    for (const el of els) {
                        const t = (el.innerText || '').toLowerCase().trim();
                        if ((t === 'continue with email' || t === 'lanjutkan dengan email' || t.includes('email') || t.includes('surel')) && t.length < 40) {
                            const btn = el.closest('.lv_third_part_sign_in_expand_new-button, .lv_third_part_sign_in_expand-button, .lv_third_part_sign_in_expand-item, [role="button"], button, div') || el;
                            btn.click();
                            return { clicked: true, text: el.innerText, tag: btn.tagName };
                        }
                    }
                    return { clicked: false };
                }""")
                log(f"[*] klik tombol email hasil: {clicked_info}")
                if not clicked_info.get("clicked"):
                    try:
                        email_btn = page.locator(
                            ".lv_third_part_sign_in_expand_new-button, "
                            "span.lv_third_part_sign_in_expand-label:has-text('email'), "
                            "span.lv_third_part_sign_in_expand-label:has-text('Email'), "
                            "[class*='lv_third_part_sign_in']:has-text('email'), "
                            "[class*='lv_third_part_sign_in']:has-text('Email'), "
                            ".lv-account-login-form-main-field:has-text('email'), "
                            "button:has-text('email')"
                        ).first
                        if email_btn.is_visible(timeout=3000):
                            email_btn.click(timeout=3000, force=True)
                    except Exception:
                        pass
                _sleep_with_cancel(2.5, stop)

            inp = page.locator("input[type='email'], input[name='username']").first
            inp.wait_for(state="visible", timeout=20000)
            log("[*] CapCut signup email form is ready")
            return
        except Exception as exc:
            last_exc = exc
            log(f"[!] error loading CapCut signup page ({exc}); retrying...")
            _sleep_with_cancel(3, stop)

    raise SignupError(f"failed opening CapCut signup page: {last_exc}")


def _fill_capcut_email(page, email: str, log, stop=None) -> None:
    """Input email and submit to proceed to Password step."""
    _raise_if_cancelled(stop)
    inp = page.locator(
        "input[type='email'], input[name='username'], input[placeholder*='email'], input[placeholder*='Email']"
    ).first
    inp.wait_for(state="visible", timeout=12000)
    try:
        inp.focus()
    except Exception:
        inp.evaluate("el => el.focus()")
    inp.fill(email)
    _sleep_with_cancel(0.6, stop)

    submit_btn = page.locator(
        "button:has-text('Lanjutkan'), button:has-text('Continue'), "
        "div[role='button']:has-text('Lanjutkan'), div[role='button']:has-text('Continue')"
    ).first
    submit_btn.click()
    _sleep_with_cancel(2.5, stop)


def _fill_capcut_password(page, password: str, log, stop=None) -> None:
    """Input password and submit to proceed to Birthday step."""
    _raise_if_cancelled(stop)
    pwd_inp = page.locator(
        "input[type='password'], input[name='password'], input[placeholder*='password'], input[placeholder*='sandi']"
    ).first
    pwd_inp.wait_for(state="visible", timeout=12000)
    try:
        pwd_inp.focus()
    except Exception:
        pwd_inp.evaluate("el => el.focus()")
    pwd_inp.fill(password)
    _sleep_with_cancel(0.6, stop)

    signup_btn = page.locator(
        "button:has-text('Sign up'), button:has-text('Daftar'), "
        "div[role='button']:has-text('Sign up'), div[role='button']:has-text('Daftar')"
    ).first
    signup_btn.click()
    _sleep_with_cancel(3.0, stop)


def _fill_capcut_birthday(page, log, stop=None) -> None:
    """If CapCut prompts for birthday, fill Year, Month, Day and submit."""
    _raise_if_cancelled(stop)
    try:
        year_input = page.locator(
            "input.gate_birthday-picker-input, input[placeholder='Year'], input[placeholder='Tahun']"
        ).first
        if year_input.is_visible(timeout=10000):
            log("[*] filling birthday information...")
            year_input.fill("1998")
            _sleep_with_cancel(0.5, stop)

            # Month: click first select wrapper
            month_box = page.locator(".gate_birthday-select, .lv-select").first
            month_box.click(force=True)
            _sleep_with_cancel(0.6, stop)
            page.locator(".lv-select-dropdown-item, .lv-select-popup-item, .lv-option, li").first.click(force=True)
            _sleep_with_cancel(0.5, stop)

            # Day: click second select wrapper
            day_box = page.locator(".gate_birthday-select, .lv-select").nth(1)
            day_box.click(force=True)
            _sleep_with_cancel(0.6, stop)
            day_items = page.locator(".lv-select-dropdown-item, .lv-select-popup-item, .lv-option, li").all()
            if len(day_items) >= 15:
                day_items[14].click(force=True)
            elif day_items:
                day_items[0].click(force=True)
            _sleep_with_cancel(0.5, stop)

            # Click Continue
            cont_btn = page.locator(
                "button:has-text('Continue'), button:has-text('Lanjutkan'), div[role='button']:has-text('Continue')"
            ).first
            cont_btn.click()
            _sleep_with_cancel(3.0, stop)
    except Exception as exc:
        log(f"[i] birthday step skipped or handled: {exc}")


def _enter_capcut_otp(page, mail, email: str, order_id: str, cfg: Config, log, stop=None) -> str:
    """Wait for 6-digit OTP code from mail provider and type it into CapCut."""
    _raise_if_cancelled(stop)
    otp_inp = page.locator(
        "input[maxlength='6'], input[autocomplete='one-time-code'], input[id*='code']"
    ).first
    otp_inp.wait_for(state="visible", timeout=20000)

    log(f"[*] waiting for CapCut verification code at {email}...")
    raw_code = mail.wait_for_code(
        order_id,
        timeout=cfg.otp_timeout_sec,
        log=log,
        cancel_cb=stop,
        email=email,
    )
    if not raw_code:
        raise SignupError("no CapCut verification code received")

    code = re.sub(r"\D", "", raw_code)[:6]
    log(f"[+] verification code found: {code}")

    _raise_if_cancelled(stop)
    try:
        otp_inp.click()
    except Exception:
        otp_inp.focus()
    _sleep_with_cancel(0.3, stop)
    otp_inp.press_sequentially(code, delay=80)
    _sleep_with_cancel(3.0, stop)

    # Click continue button if it's still visible and enabled
    try:
        cont_btn = page.locator(
            "button[type='submit'], button:has-text('Continue'), button:has-text('Lanjutkan')"
        ).first
        if cont_btn.is_visible(timeout=1000) and cont_btn.is_enabled():
            cont_btn.click()
    except Exception:
        pass

    return code


def _dismiss_all_onboarding_overlays(page, log, stop=None) -> None:
    """Aggressively dismiss all post-login dialogs:
    1. Dialog 1: Role questionnaire ('Which of the following roles best describes you?') -> click 'Skip' or 'Personal user'
    2. Dialog 2: Outer modal ('What do you want to create?' / templates) -> click '✕' close button & Escape
    3. Tooltips & guide popovers ('Your library is here') -> Escape & close
    """
    _raise_if_cancelled(stop)
    log("[*] membersihkan kedua dialog onboarding & pop-up pasca-login...")

    # Initial Escape key presses to dismiss simple popovers immediately
    for _ in range(2):
        try:
            page.keyboard.press("Escape")
        except Exception:
            pass
        _sleep_with_cancel(0.2, stop)

    for attempt in range(4):
        _raise_if_cancelled(stop)
        dismissed = False

        # --- TAHAP 1: DIALOG 1 (KUESIONER PERAN: 'Which of the following roles...') ---
        try:
            survey_handled = page.evaluate("""() => {
                function triggerClick(el) {
                    if (!el) return;
                    try { el.scrollIntoView({ behavior: 'instant', block: 'center' }); } catch(e) {}
                    el.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true }));
                    el.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true }));
                    el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
                    el.click();
                }

                // Check if questionnaire text is visible
                const all = Array.from(document.querySelectorAll('*'));
                const hasSurvey = all.some(e => {
                    const t = (e.innerText || '').toLowerCase();
                    return t.includes('which of the following roles') || 
                           t.includes('personalize your experience') ||
                           t.includes('select only 1') ||
                           t.includes('peran mana yang paling');
                });

                if (hasSurvey) {
                    // 1. Look for exact 'Skip' or 'Lewati' button on the card
                    const skipBtn = all.find(el => {
                        if (el.closest('.subscriptionModal-wrapper')) return false;
                        const t = (el.innerText || el.textContent || '').trim().toLowerCase();
                        if (t !== 'skip' && t !== 'lewati') return false;
                        const r = el.getBoundingClientRect();
                        return r.width > 0 && r.height > 0 && r.width < 140 && r.height < 60;
                    });
                    if (skipBtn) {
                        triggerClick(skipBtn);
                        return 'skip_clicked';
                    }

                    // 2. Fallback: Click 'Personal user' card to complete and close questionnaire
                    const personalCard = all.find(el => {
                        const t = (el.innerText || '').trim().toLowerCase();
                        const r = el.getBoundingClientRect();
                        return (t === 'personal user' || t.startsWith('personal user') || t === 'pengguna pribadi') && r.height > 20;
                    });
                    if (personalCard) {
                        const target = personalCard.closest('[role="button"], div[class*="item"], div[class*="card"], button') || personalCard;
                        triggerClick(target);
                        return 'personal_user_clicked';
                    }
                }
                return null;
            }""")

            if survey_handled:
                log(f"[+] Dialog 1 (kuesioner peran) ditutup via JS ({survey_handled})")
                dismissed = True
                _sleep_with_cancel(0.5, stop)
        except Exception:
            pass

        # Playwright fallback for Dialog 1
        try:
            skip_loc = page.get_by_text(re.compile(r"^\s*(Skip|Lewati)\s*$", re.I)).first
            if skip_loc.is_visible(timeout=500):
                if not skip_loc.evaluate("el => el.closest('.subscriptionModal-wrapper') !== null"):
                    skip_loc.click(timeout=1000, force=True)
                    log("[+] Dialog 1 ditutup: tombol 'Skip' diklik via Playwright")
                    dismissed = True
                    _sleep_with_cancel(0.5, stop)
        except Exception:
            pass

        # --- TAHAP 2: DIALOG 2 (MODAL 'What do you want to create?' / TEMPLATES) ---
        try:
            modal_handled = page.evaluate("""() => {
                function triggerClick(el) {
                    if (!el) return;
                    try { el.scrollIntoView({ behavior: 'instant', block: 'center' }); } catch(e) {}
                    el.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true }));
                    el.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true }));
                    el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
                    el.click();
                }

                // Check for close buttons (✕) outside subscription modal
                const closeBtns = Array.from(document.querySelectorAll(
                    '.lv-modal-close-btn, .lv-modal-close-icon, .lv-modal-close, ' +
                    '[aria-label="Close"], [aria-label="close"], [aria-label="Tutup"], ' +
                    '[class*="modal-close"], [class*="close-icon"], [class*="closeBtn"], button[class*="close"]'
                )).filter(b => !b.closest('.subscriptionModal-wrapper'));

                for (const btn of closeBtns) {
                    const r = btn.getBoundingClientRect();
                    if (r.width > 0 && r.height > 0) {
                        triggerClick(btn);
                        return 'close_x_clicked';
                    }
                }
                return null;
            }""")

            if modal_handled:
                log(f"[+] Dialog 2 (modal utama) ditutup via tombol '✕' ({modal_handled})")
                dismissed = True
                _sleep_with_cancel(0.5, stop)
        except Exception:
            pass

        # Playwright fallback for Dialog 2 close button
        try:
            close_loc = page.locator(
                ".lv-modal-close-btn, .lv-modal-close, button[aria-label='Close'], [aria-label='Close'], [aria-label='Tutup'], "
                "[class*='modal-close'], [class*='close-icon'], [class*='closeBtn']"
            ).first
            if close_loc.is_visible(timeout=500):
                if not close_loc.evaluate("el => el.closest('.subscriptionModal-wrapper') !== null"):
                    close_loc.click(timeout=1000, force=True)
                    log("[+] Dialog 2 ditutup: tombol '✕' (close) diklik via Playwright")
                    dismissed = True
                    _sleep_with_cancel(0.5, stop)
        except Exception:
            pass

        # --- TAHAP 3: ESCAPE KEY (Menutup overlay / modal / tooltip yang tersisa) ---
        for _ in range(2):
            try:
                page.keyboard.press("Escape")
            except Exception:
                pass
            _sleep_with_cancel(0.2, stop)

        # Tooltip / guide popover dismiss (e.g. 'Your library is here')
        try:
            page.evaluate("""() => {
                const tipBtn = document.querySelector('[class*="popover"] button, [class*="tooltip"] button, [class*="guide"] button, [class*="tour"] button');
                if (tipBtn && !tipBtn.closest('.subscriptionModal-wrapper')) {
                    tipBtn.click();
                }
            }""")
        except Exception:
            pass

        # --- TAHAP 4: CLEANUP LINGERING MASKS (Jika masih ada backdrop yang menutupi dashboard) ---
        if attempt >= 1:
            try:
                hidden_count = page.evaluate("""() => {
                    let count = 0;
                    document.querySelectorAll('.lv-modal-mask, .lv-modal-wrap, .lv-modal').forEach(el => {
                        if (!el.closest('.subscriptionModal-wrapper') && !el.querySelector('.subscriptionModal-wrapper')) {
                            el.style.display = 'none';
                            count++;
                        }
                    });
                    return count;
                }""")
                if hidden_count > 0:
                    log(f"[*] {hidden_count} layer backdrop overlay dinonaktifkan")
            except Exception:
                pass

        # Periksa apakah masih ada modal atau kuesioner yang tersisa
        try:
            still_blocked = page.evaluate("""() => {
                const hasModal = Array.from(document.querySelectorAll('.lv-modal, .lv-modal-wrap, .lv-modal-mask')).some(
                    m => !m.closest('.subscriptionModal-wrapper') && !m.querySelector('.subscriptionModal-wrapper') && m.style.display !== 'none'
                );
                const hasSurveyText = (document.body ? document.body.innerText || '' : '').toLowerCase().includes('which of the following roles');
                return hasModal || hasSurveyText;
            }""")
        except Exception:
            still_blocked = False

        if not still_blocked:
            log("[+] Kedua dialog onboarding berhasil ditutup sepenuhnya!")
            break

        _sleep_with_cancel(0.5, stop)

    _sleep_with_cancel(0.5, stop)


def _handle_capcut_onboarding(page, log, stop=None) -> None:
    """Handle post-signup 'Space Name' creation screen, team invite step, and 'Open CapCut' button."""
    _raise_if_cancelled(stop)
    log("[*] menangani onboarding pasca-signup (Space Name / Pembuatan Ruang)...")

    deadline = time.time() + 25
    while time.time() < deadline:
        _raise_if_cancelled(stop)

        txt = _page_text(page).lower()
        if "we can't sign you up for security reasons" in txt:
            raise SignupBlocked(
                "CapCut security restriction triggered. "
                "Recommendation: run with headless=false or use a residential proxy."
            )

        if "my-edit" in page.url.lower():
            break

        # 1. Fill Space Name input if visible
        try:
            space_input_handled = page.evaluate("""() => {
                const inputs = Array.from(document.querySelectorAll('input[type="text"], input:not([type])'));
                const spaceInp = inputs.find(inp => {
                    const p = (inp.placeholder || '').toLowerCase();
                    const n = (inp.name || '').toLowerCase();
                    const aria = (inp.getAttribute('aria-label') || '').toLowerCase();
                    const r = inp.getBoundingClientRect();
                    return r.width > 50 && r.height > 20 && (
                        p.includes('space') || p.includes('ruang') || p.includes('name') || p.includes('nama') ||
                        n.includes('space') || n.includes('workspace') || aria.includes('space') || aria.includes('ruang')
                    );
                }) || (inputs.length === 1 && inputs[0].getBoundingClientRect().width > 100 ? inputs[0] : null);

                if (spaceInp) {
                    if (!spaceInp.value || spaceInp.value.trim().length === 0) {
                        spaceInp.value = "My Space";
                        spaceInp.dispatchEvent(new Event('input', { bubbles: true }));
                        spaceInp.dispatchEvent(new Event('change', { bubbles: true }));
                    }
                    return true;
                }
                return false;
            }""")
            if space_input_handled:
                log("[*] onboarding: nama ruang (Space Name) terisi")
        except Exception:
            pass

        # 2. Click Next / Create / Continue / Buka CapCut / Skip button via JS
        try:
            btn_clicked = page.evaluate("""() => {
                function triggerClick(el) {
                    if (!el) return false;
                    try { el.scrollIntoView({ behavior: 'instant', block: 'center' }); } catch(e) {}
                    el.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true }));
                    el.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true }));
                    el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
                    el.click();
                    return true;
                }

                // Check for 'Skip' / 'Maybe later' / 'Not now' (e.g. invite members step)
                const skipCandidates = Array.from(document.querySelectorAll('button, a, span, div, [role="button"]'));
                const skipBtn = skipCandidates.find(el => {
                    const t = (el.innerText || el.textContent || '').trim().toLowerCase();
                    const r = el.getBoundingClientRect();
                    return (t === 'skip' || t === 'lewati' || t === 'maybe later' || t === 'not now' || t === 'nanti saja') &&
                           r.width > 20 && r.height > 15;
                });
                if (skipBtn) {
                    triggerClick(skipBtn);
                    return 'skip_clicked: ' + skipBtn.innerText;
                }

                // Look for Next / Create / Continue / Buka CapCut / Start creating / Mulai
                const actionBtns = Array.from(document.querySelectorAll('button, [role="button"], a, div.lv-btn'));
                const targetBtn = actionBtns.find(el => {
                    const t = (el.innerText || el.textContent || '').trim().toLowerCase();
                    const r = el.getBoundingClientRect();
                    if (r.width < 40 || r.height < 20) return false;
                    return t === 'next' || t === 'lanjut' || t === 'lanjutkan' ||
                           t === 'create' || t === 'buat' || t.includes('create space') || t.includes('buat ruang') ||
                           t === 'continue' || t === 'start creating' || t === 'buka capcut' || t === 'open capcut' ||
                           t === 'get started' || t === 'mulai' || t === 'mulailah' ||
                           el.getAttribute('type') === 'submit';
                });
                if (targetBtn) {
                    triggerClick(targetBtn);
                    return 'btn_clicked: ' + targetBtn.innerText;
                }

                // Try pressing Enter on any active space input
                const activeInp = document.querySelector('input:focus, input[type="text"]');
                if (activeInp) {
                    activeInp.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true }));
                    activeInp.dispatchEvent(new KeyboardEvent('keyup', { key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true }));
                    return 'enter_pressed';
                }

                return null;
            }""")
            if btn_clicked:
                log(f"[*] onboarding space: {btn_clicked}")
                _sleep_with_cancel(1.2, stop)
        except Exception:
            pass

        # 3. Playwright native fallback clicks
        try:
            nxt = page.locator(
                "button:has-text('Next'), button:has-text('Lanjut'), button:has-text('Lanjutkan'), "
                "button:has-text('Create'), button:has-text('Buat'), button:has-text('Continue'), "
                "button:has-text('Buka CapCut'), button:has-text('Open CapCut'), button:has-text('Start creating'), "
                "button:has-text('Skip'), button:has-text('Lewati'), button[type='submit']"
            ).first
            if nxt.is_visible(timeout=800):
                nxt.click(force=True)
                log("[*] onboarding space: tombol wizard diklik via Playwright")
                _sleep_with_cancel(1.2, stop)
        except Exception:
            pass

        if "my-edit" in page.url.lower():
            break

        _sleep_with_cancel(1.0, stop)

    # If still not on my-edit, force navigate to my-edit
    if "my-edit" not in page.url.lower():
        log("[*] menuju dashboard CapCut (my-edit)...")
        try:
            page.goto("https://www.capcut.com/my-edit", wait_until="domcontentloaded", timeout=20000)
        except Exception as exc:
            log(f"[i] navigation note: {exc}")
        _sleep_with_cancel(2.0, stop)

    _dismiss_all_onboarding_overlays(page, log, stop=stop)


def _clean_payment_url(urls: list[str]) -> Optional[str]:
    """Find the best payment/cashier/checkout URL from a list of captured URLs."""
    import urllib.parse
    candidates = []
    for raw_u in urls:
        if not raw_u or not isinstance(raw_u, str):
            continue
        u = raw_u.replace(r"\/", "/").replace('"', '').replace("'", "").strip()
        # Only unquote if the entire URL is percent-encoded (e.g. starts with http%3a / https%3a)
        # Never unquote normal URLs to prevent corrupting base64 tokens (+ turning into space)
        if u.lower().startswith("http%3a") or u.lower().startswith("https%3a"):
            try:
                u = urllib.parse.unquote(u)
            except Exception:
                pass
        if not u.startswith("http"):
            continue
        low = u.lower()
        # Direct Pipopay or ByteDance Cashier URLs — keep immediately!
        if any(k in low for k in ["pipopay.com", "agreement-cashier", "pipoux_checkout", "cashier.bytedance.com"]):
            if not any(low.endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".svg", ".woff", ".woff2"]):
                candidates.append(u)
            continue
        if any(bad in low for bad in [
            ".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".woff2",
            "favicon", "analytics", "log/app", "telemetry", "mon/", "report", "beacon",
            "/api/", "api-", "get_subscribe_info"
        ]):
            continue
        candidates.append(u)

    # Priority 1: cashier URL containing token= query param (THE EXACT CHECKOUT CASHIER LINK!)
    for c in candidates:
        low = c.lower()
        if ("pipopay.com" in low or "agreement-cashier" in low) and "token=" in low:
            return c

    # Priority 2: pipopay.com / agreement-cashier with any query parameter
    for c in candidates:
        low = c.lower()
        if ("pipopay.com" in low or "agreement-cashier" in low) and "?" in low:
            return c

    # Priority 3: any pipopay.com or agreement-cashier
    for c in candidates:
        low = c.lower()
        if "pipopay.com" in low or "agreement-cashier" in low or "pipoux_checkout" in low:
            return c

    # Priority 4: other gateways (bytedance cashier, stripe, buy.tiktok)
    for c in candidates:
        low = c.lower()
        if any(h in low for h in ["cashier.bytedance.com", "stripe.com", "buy.tiktok.com", "dlocal.com"]):
            return c

    # Priority 5: any URL containing cashier or checkout
    for c in candidates:
        low = c.lower()
        if "cashier" in low or "checkout" in low or "agreement-cashier" in low:
            return c

    return None


def _find_urls_in_dict(obj, out_list: list[str]) -> None:
    """Recursively search JSON objects for checkout/cashier URLs."""
    import urllib.parse
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                v_clean = v.replace(r"\/", "/")

                # If v_clean is a JSON string, recursively parse it
                if (v_clean.startswith("{") and v_clean.endswith("}")) or (v_clean.startswith("[") and v_clean.endswith("]")):
                    try:
                        import json
                        parsed_inner = json.loads(v_clean)
                        _find_urls_in_dict(parsed_inner, out_list)
                    except Exception:
                        pass

                if "http://" in v_clean or "https://" in v_clean:
                    matches = re.findall(r'https?://[^\s"\'<>\\]+', v_clean)
                    for m in matches:
                        low_m = m.lower()
                        if any(c in low_m for c in ["pipopay", "cashier", "checkout", "agreement-cashier", "pipoux"]):
                            out_list.append(m)

                k_low = str(k).lower()
                if any(term in k_low for term in ["cashier_url", "checkout_url", "pay_url", "payment_url", "redirect_url", "jump_url", "url", "schema"]):
                    if v_clean.startswith("http://") or v_clean.startswith("https://"):
                        if any(c in v_clean.lower() for c in ["cashier", "checkout", "pay", "subscribe", "stripe", "buy", "pipopay"]):
                            out_list.append(v_clean)
            elif isinstance(v, (dict, list)):
                _find_urls_in_dict(v, out_list)
    elif isinstance(obj, list):
        for item in obj:
            _find_urls_in_dict(item, out_list)
        for item in obj:
            _find_urls_in_dict(item, out_list)


def _process_capcut_upgrade(context, page, log, stop=None, only_7days: bool = True) -> tuple[str, str]:
    """Check CapCut upgrade offers (7-day trial or team discount) and retrieve payment link.

    Returns (promo_info, payment_link).
    """
    _raise_if_cancelled(stop)
    log("[>] [UPGRADE ] Memeriksa menu upgrade akun...")

    # Set up listeners for payment redirects / popups / network calls
    captured_urls: list[str] = []
    opened_pages = []

    def _on_new_page(p):
        opened_pages.append(p)
        try:
            p.on("framenavigated", lambda f: captured_urls.append(f.url) if f.url and ("pipopay" in f.url.lower() or "cashier" in f.url.lower()) else None)
        except Exception:
            pass

    def _on_request(req):
        try:
            u = req.url
            low = u.lower()
            if "pipopay.com" in low or "agreement-cashier" in low or "pipoux_checkout" in low or "cashier.bytedance.com" in low:
                captured_urls.append(u)
                return
            if any(k in low for k in [
                "cashier", "checkout", "buy.tiktok", "stripe.com", "dlocal", "midtrans", "xendit",
                "order/create", "order_create", "create_order", "pay_url", "checkout_url", "cashier_url", "init_trade", "query_trade"
            ]):
                if not any(u.endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".svg", ".woff", ".woff2"]):
                    captured_urls.append(u)
        except Exception:
            pass

    def _on_response(res):
        try:
            u = res.url.lower()
            if any(k in u for k in ["pipopay", "cashier", "order", "subscribe", "pay", "checkout", "subscription", "commerce", "trade", "vip", "benefit"]):
                try:
                    text = res.text()
                    if any(k in text.lower() for k in ["pipopay", "cashier", "agreement-cashier", "pipoux"]):
                        clean_text = text.replace(r"\/", "/")
                        matches = re.findall(r'https?://[^\s"\'<>\\]*(?:pipopay\.com|agreement-cashier|pipoux|cashier\.bytedance)[^\s"\'<>\\]*', clean_text)
                        for m in matches:
                            captured_urls.append(m)
                except Exception:
                    pass
                try:
                    data = res.json()
                    if isinstance(data, dict):
                        resp_field = data.get("response")
                        if isinstance(resp_field, str) and (resp_field.startswith("{") or "cashier" in resp_field):
                            try:
                                import json
                                parsed_resp = json.loads(resp_field)
                                if isinstance(parsed_resp, dict):
                                    pipo_agg = parsed_resp.get("pipo_aggregate_pay_info") or {}
                                    if isinstance(pipo_agg, dict):
                                        curl = pipo_agg.get("cashier_url")
                                        if curl and isinstance(curl, str):
                                            captured_urls.append(curl.replace(r"\/", "/"))
                                    direct_curl = parsed_resp.get("cashier_url") or parsed_resp.get("pay_url")
                                    if direct_curl and isinstance(direct_curl, str):
                                        captured_urls.append(direct_curl.replace(r"\/", "/"))
                                _find_urls_in_dict(parsed_resp, captured_urls)
                            except Exception:
                                pass
                    _find_urls_in_dict(data, captured_urls)
                except Exception:
                    pass
        except Exception:
            pass

    try:
        context.on("page", _on_new_page)
        page.on("request", _on_request)
        page.on("response", _on_response)
    except Exception:
        pass

    # Ensure we are on the dashboard (my-edit)
    settle_deadline = time.time() + 15
    while time.time() < settle_deadline:
        _raise_if_cancelled(stop)
        curr_url = page.url.lower()
        if "my-edit" in curr_url:
            break
        if "signup" not in curr_url and "login" not in curr_url:
            break
        _sleep_with_cancel(1.0, stop)

    if "my-edit" not in page.url.lower():
        log("[*] menuju dashboard CapCut (my-edit)...")
        try:
            page.goto("https://www.capcut.com/my-edit", wait_until="domcontentloaded", timeout=20000)
        except Exception as exc:
            log(f"[i] navigation note: {exc}")

    # Allow dashboard and onboarding elements to fully render
    log("[*] menunggu dashboard dan dialog onboarding CapCut...")
    _sleep_with_cancel(4.0, stop)

    # Dismiss questionnaires (role selection dialog, Agent mode tooltip, greeting dialogs)
    _dismiss_all_onboarding_overlays(page, log, stop=stop)

    # Hook window.open early to intercept cashier popup windows
    try:
        page.evaluate("""() => {
            if (!window.__captured_open_urls) {
                window.__captured_open_urls = [];
                const orig = window.open;
                window.open = function(url, ...args) {
                    if (url) window.__captured_open_urls.push(String(url));
                    return orig ? orig.apply(this, [url, ...args]) : null;
                };
            }
        }""")
    except Exception:
        pass

    # Find and click the "Upgrade" button in header (button.credit-section or text 'Upgrade')
    log("[>] [UPGRADE ] Mencari dan mengklik tombol Upgrade di header CapCut...")
    modal_opened = False

    for attempt in range(5):
        _raise_if_cancelled(stop)
        if attempt > 0 and not modal_opened:
            _dismiss_all_onboarding_overlays(page, log, stop=stop)
        log(f"[*] mencoba klik tombol Upgrade (percobaan {attempt + 1}/5)...")

        # 1. Direct click on button.credit-section or header element containing 'Upgrade'
        try:
            clicked_info = page.evaluate("""() => {
                const credBtn = document.querySelector('button.credit-section, [class*="credit-section"]');
                if (credBtn) {
                    credBtn.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true }));
                    credBtn.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true }));
                    credBtn.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
                    credBtn.click();
                    return { clicked: true, tag: credBtn.tagName, text: credBtn.innerText };
                }
                const all = Array.from(document.querySelectorAll('header *, [class*="header"] *, div, button, span, a'));
                const el = all.find(e => {
                    const t = (e.innerText || e.textContent || '').trim();
                    const rect = e.getBoundingClientRect();
                    return (t.includes('Upgrade') || t.includes('Tingkatkan')) && rect.top < 80 && rect.width > 0 && rect.height > 0;
                });
                if (el) {
                    const btn = el.closest('button, [role="button"], a, div') || el;
                    btn.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true }));
                    btn.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true }));
                    btn.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
                    btn.click();
                    return { clicked: true, tag: btn.tagName, text: el.innerText };
                }
                return { clicked: false };
            }""")
            if clicked_info.get("clicked"):
                log(f"[*] tombol Upgrade diklik via JS: {clicked_info}")
        except Exception:
            pass

        # 2. Native Playwright locator fallback
        try:
            upg_loc = page.locator(
                "button.credit-section, [class*='credit-section'], "
                "span.upgrade-text, [class*='upgrade-text'], [class*='upgrade-btn'], "
                "button:has-text('Upgrade'), button:has-text('Tingkatkan')"
            ).first
            if upg_loc.is_visible(timeout=1500):
                upg_loc.click(force=True)
                log("[*] tombol Upgrade diklik via locator")
        except Exception:
            pass

        # 3. Check if pricing modal opened
        for _ in range(4):
            _sleep_with_cancel(0.8, stop)
            modal_opened = page.evaluate("""() => {
                const modal = document.querySelector(
                    '.subscriptionModal-wrapper, [class*="subscriptionModal"], [class*="pricingModal"], ' +
                    '[class*="vip-modal"], [class*="vipModal"], [role="dialog"].lv-modal, .lv-modal-content, .lv-modal'
                );
                if (!modal) return false;
                const txt = (modal.innerText || '').toLowerCase();
                return txt.includes('choose your plan') || txt.includes('pilih paket') || txt.includes('monthly') || txt.includes('pro') || txt.includes('tingkatkan');
            }""")
            if modal_opened:
                break

        if modal_opened:
            log("[+] Popup pricing terdeteksi terbuka!")
            break

        # 4. Fallback: Avatar dropdown -> Upgrade
        log("[*] mencoba fallback via menu Avatar dropdown...")
        try:
            page.evaluate("""() => {
                const avatars = Array.from(document.querySelectorAll('img, [class*="avatar"], [class*="user"], [class*="header"] *'));
                const av = avatars.find(el => {
                    const rect = el.getBoundingClientRect();
                    return rect.top < 80 && rect.right > window.innerWidth - 120 && rect.width >= 20 && rect.height >= 20;
                });
                if (av) {
                    av.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
                    av.click();
                }
            }""")
            _sleep_with_cancel(1.0, stop)
            upg_drop = page.locator(
                "[class*='dropdown'], [class*='popover'], [class*='menu'], .header-right"
            ).locator("button:has-text('Upgrade'), div:has-text('Upgrade'), span:has-text('Upgrade'), button:has-text('Tingkatkan')").first
            if upg_drop.is_visible(timeout=1500):
                upg_drop.click(force=True)
                log("[*] tombol Upgrade di dropdown avatar diklik")
        except Exception:
            pass

        # Check modal again
        for _ in range(3):
            _sleep_with_cancel(0.8, stop)
            modal_opened = page.evaluate("""() => {
                const modal = document.querySelector(
                    '.subscriptionModal-wrapper, [class*="subscriptionModal"], [class*="pricingModal"], ' +
                    '[class*="vip-modal"], [class*="vipModal"], [role="dialog"].lv-modal, .lv-modal-content, .lv-modal'
                );
                if (!modal) return false;
                const txt = (modal.innerText || '').toLowerCase();
                return txt.includes('choose your plan') || txt.includes('pilih paket') || txt.includes('monthly') || txt.includes('pro') || txt.includes('tingkatkan');
            }""")
            if modal_opened:
                break

        if modal_opened:
            log("[+] Popup pricing terdeteksi terbuka via avatar!")
            break

    if not modal_opened:
        log("[!] popup pricing tidak muncul setelah beberapa percobaan")
        return "", ""

    # Wait for the pricing modal cards to load content (prices & buttons)
    log("[*] menunggu kartu penawaran harga termuat...")
    _sleep_with_cancel(2.0, stop)

    # SCROLL DOWN FIRST inside the modal to inspect 0rp / 7-day trial offers
    def _scroll_modal_down():
        try:
            page.evaluate("""() => {
                const modal = document.querySelector(
                    '.subscriptionModal-wrapper, [class*="subscriptionModal"], [class*="pricingModal"], ' +
                    '[class*="vip-modal"], [class*="vipModal"], [role="dialog"], .lv-modal-content, .lv-modal, .lv-modal-body'
                );
                if (modal) {
                    modal.scrollTop = modal.scrollHeight;
                    Array.from(modal.querySelectorAll('*')).forEach(el => {
                        if (el.scrollHeight > el.clientHeight && el.clientHeight > 50) {
                            el.scrollTop = el.scrollHeight;
                        }
                    });
                }
                window.scrollBy({ top: 600, behavior: 'instant' });
            }""")
        except Exception:
            pass
        try:
            page.mouse.wheel(0, 600)
        except Exception:
            pass
        _sleep_with_cancel(1.0, stop)

    log("[*] men-scroll modal ke bawah untuk memeriksa penawaran diskon Trial 7 Hari (Rp0)...")
    _scroll_modal_down()

    promo_data = None
    cards_deadline = time.time() + 15
    while time.time() < cards_deadline:
        _raise_if_cancelled(stop)
        res = page.evaluate(r"""() => {
            const modal = document.querySelector(
                '.subscriptionModal-wrapper, [class*="subscriptionModal"], [class*="pricingModal"], ' +
                '[class*="vip-modal"], [class*="vipModal"], [role="dialog"], .lv-modal-content, .lv-modal'
            );
            if (!modal) return { ready: false };
            const text = modal.innerText || '';
            const lower = text.toLowerCase();

            // Modal cards must have loaded 'pro' or price elements
            if (!lower.includes('pro') && !lower.includes('free') && !lower.includes('gratis') && !lower.includes('paket') && !lower.includes('plan')) {
                return { ready: false, sample: text.slice(0, 150) };
            }

            // Find elements containing 'pro'
            const allEls = Array.from(modal.querySelectorAll('*'));
            const proCard = allEls.find(el => {
                const t = (el.innerText || '').toLowerCase();
                const r = el.getBoundingClientRect();
                return r.height > 100 && r.width > 80 && r.width < 500 && t.includes('pro') && !t.includes('ultra');
            });
            const proText = proCard ? (proCard.innerText || '') : text;

            // 1. Comprehensive Check for 7-Day Trial on Pro (Indonesian & English: Rp0 / 7-day free trial / trial 7 hari)
            const isTrial7Days = (
                /7[\s-]*(?:day|hari)[\s\S]{0,80}?(?:free|gratis|rp\s*0|0\s*rp|\$0|uji\s*coba|trial)/i.test(text) ||
                /(?:free|gratis|rp\s*0|0\s*rp|\$0|uji\s*coba|trial)[\s\S]{0,80}?7[\s-]*(?:day|hari)/i.test(text) ||
                /7[\s-]*(?:day|hari)\s*(?:free\s*trial|trial|uji\s*coba)/i.test(text) ||
                /(?:coba|uji\s*coba|trial)\s*(?:gratis\s*)?7[\s-]*(?:day|hari)/i.test(text) ||
                ((/7[\s-]*(?:day|hari)/i.test(text)) && (
                    /rp\s*0\b/i.test(text) || /0\s*rp\b/i.test(text) || /\$0\b/i.test(text) ||
                    /free/i.test(text) || /gratis/i.test(text) || /trial/i.test(text) || /uji\s*coba/i.test(text)
                ))
            );
            const has7Days = !!isTrial7Days;

            // 2. Comprehensive Check for Pro discount / promo
            const hasProDiscount = (
                /%\s*off/i.test(text) ||
                /diskon/i.test(text) ||
                /save/i.test(text) ||
                /potongan/i.test(text) ||
                /hemat/i.test(text) ||
                /promo/i.test(text) ||
                /limited\s*time/i.test(text) ||
                /waktu\s*terbatas/i.test(text) ||
                /penawaran/i.test(text) ||
                /special\s*offer/i.test(text) ||
                /yearly\s*-\s*%\s*off/i.test(text)
            );

            // 3. Strikethrough price (original price crossed out)
            const hasDelPrice = modal.querySelector('del, s, strike, [class*="origin-price"], [class*="original-price"], [class*="old-price"], [class*="discount"]') !== null;

            // 4. Team discount
            const hasTeams = /team[\s\S]*?(?:%\s*off|diskon|save|\d+%\s*off)/i.test(text) ||
                             /tim[\s\S]*?(?:%\s*off|diskon|hemat|\d+%\s*off)/i.test(text);

            const hasAnyDiscount = has7Days || hasProDiscount || hasDelPrice || hasTeams;

            let trialText = "";
            if (has7Days) {
                const m = text.match(/(?:rp\s*0[^\n]*\n*for 7 days|for 7 days|selama 7 hari|trial 7 hari|7-day free trial|uji coba gratis 7 hari|coba gratis)/i);
                trialText = m ? m[0].replace(/\s+/g, ' ') : "Trial 7 Hari (Rp0)";
            }

            let teamsText = "";
            if (hasTeams) {
                const m = text.match(/(?:teams?[^\n]*?(?:%\s*off|diskon|save)[^\n]*)/i);
                teamsText = m ? m[0].replace(/\s+/g, ' ') : "Teams Discount";
            }

            return {
                ready: true,
                has7Days: !!has7Days,
                hasProDiscount: !!hasProDiscount,
                hasDelPrice: !!hasDelPrice,
                hasTeams: !!hasTeams,
                hasAnyDiscount: !!hasAnyDiscount,
                trialText: trialText,
                teamsText: teamsText,
                sample: text.slice(0, 300)
            };
        }""")

        if res.get("ready"):
            promo_data = res
            log(f"[*] kartu harga siap! (has7Days={res.get('has7Days')}, hasDiskon={res.get('hasAnyDiscount')}, hasDelPrice={res.get('hasDelPrice')})")
            break
        _sleep_with_cancel(0.8, stop)

    if not promo_data or not promo_data.get("ready"):
        log("[!] kartu penawaran harga tidak dapat dimuat")
        return "", ""

    has_7days = promo_data.get("has7Days", False)
    has_pro_discount = promo_data.get("hasProDiscount", False) or promo_data.get("hasDelPrice", False)
    has_teams = promo_data.get("hasTeams", False)
    has_any_discount = promo_data.get("hasAnyDiscount", False)

    # If 7-day trial is not on the default Monthly tab, check the Yearly tab!
    if not has_7days:
        log("[*] Memeriksa apakah ada penawaran Trial 7 Hari di tab Tahunan (Yearly)...")
        switched = page.evaluate("""() => {
            const tabs = Array.from(document.querySelectorAll('button.subscriptionModal-tab, [class*="subscriptionModal-tab"]'));
            const yTab = tabs.find(t => {
                const txt = (t.innerText || '').toLowerCase();
                return txt.includes('yearly') || txt.includes('tahunan') || txt.includes('year');
            });
            if (yTab) {
                yTab.click();
                return true;
            }
            return false;
        }""")
        if switched:
            _sleep_with_cancel(1.2, stop)
            log("[*] men-scroll ke bawah di tab Tahunan (Yearly)...")
            _scroll_modal_down()
            yearly_res = page.evaluate(r"""() => {
                const modal = document.querySelector(
                    '.subscriptionModal-wrapper, [class*="subscriptionModal"], [class*="pricingModal"], ' +
                    '[class*="vip-modal"], [class*="vipModal"], [role="dialog"], .lv-modal-content, .lv-modal'
                );
                if (!modal) return { has7Days: false };
                const text = modal.innerText || '';
                const isTrial7Days = (
                    /7[\s-]*(?:day|hari)[\s\S]{0,80}?(?:free|gratis|rp\s*0|0\s*rp|\$0|uji\s*coba|trial)/i.test(text) ||
                    /(?:free|gratis|rp\s*0|0\s*rp|\$0|uji\s*coba|trial)[\s\S]{0,80}?7[\s-]*(?:day|hari)/i.test(text) ||
                    /7[\s-]*(?:day|hari)\s*(?:free\s*trial|trial|uji\s*coba)/i.test(text) ||
                    /(?:coba|uji\s*coba|trial)\s*(?:gratis\s*)?7[\s-]*(?:day|hari)/i.test(text) ||
                    ((/7[\s-]*(?:day|hari)/i.test(text)) && (
                        /rp\s*0\b/i.test(text) || /0\s*rp\b/i.test(text) || /\$0\b/i.test(text) ||
                        /free/i.test(text) || /gratis/i.test(text) || /trial/i.test(text) || /uji\s*coba/i.test(text)
                    ))
                );
                let trialText = "";
                if (isTrial7Days) {
                    const m = text.match(/(?:rp\s*0[^\n]*\n*for 7 days|for 7 days|selama 7 hari|trial 7 hari|7-day free trial|uji coba gratis 7 hari|coba gratis)/i);
                    trialText = m ? m[0].replace(/\s+/g, ' ') : "Trial 7 Hari (Rp0)";
                }
                return { has7Days: !!isTrial7Days, trialText: trialText };
            }""")
            if yearly_res.get("has7Days"):
                has_7days = True
                promo_data["trialText"] = yearly_res.get("trialText")
                log(f"[+] [TRIAL 7 HARI] Ditemukan penawaran Trial 7 Hari (Rp0) di tab Tahunan!")

    # Deteksi diskon promo / trial 7 hari & tentukan target paket
    target_plan = "pro"
    promo_info = ""

    if has_7days:
        target_plan = "pro"
        promo_info = promo_data.get("trialText") or "Trial 7 Hari (Rp0)"
        log(f"[+] [TRIAL 7 HARI] Ditemukan diskon Trial 7 Hari (Rp0): {promo_info}")
    elif has_pro_discount and not only_7days:
        target_plan = "pro"
        promo_info = "Diskon Promo Pro CapCut"
        log(f"[+] [DISKON PRO ] Ditemukan penawaran Diskon Promo Pro!")
    elif has_teams and not only_7days:
        target_plan = "teams"
        promo_info = promo_data.get("teamsText") or "Teams Discount"
        log(f"[+] [DISKON TIM ] Ditemukan penawaran: {promo_info}")
    elif has_any_discount and not only_7days:
        target_plan = "pro"
        promo_info = "Diskon Promo CapCut"
        log(f"[+] [DISKON     ] Ditemukan promo diskon pada akun ini!")
    else:
        # Tidak ada penawaran Trial 7 Hari (hanya harga normal seperti Rp144.000 /month)
        # JANGAN klik Upgrade / checkout! Melewati akun ini.
        log("[-] [NO TRIAL] Akun ini TIDAK memiliki promo Trial 7 Hari (Rp0).")
        log("[*] Melewati checkout pembayaran. Menutup dialog...")
        try:
            page.keyboard.press("Escape")
            page.evaluate("""() => {
                const x = document.querySelector('.subscriptionModal-close, [aria-label="Close"], .lv-modal-close-btn');
                if (x) x.click();
            }""")
        except Exception:
            pass
        return "", ""

    # Preserve any valid cashier URLs already captured from init_trade / query_trade
    captured_urls = [u for u in captured_urls if any(k in u.lower() for k in ["pipopay.com", "agreement-cashier", "pipoux_checkout", "cashier.bytedance.com"])]

    # Click the upgrade button inside the card of the chosen plan
    log(f"[*] memilih paket '{target_plan.upper()}' dan membuka link pembayaran...")
    btn_res = page.evaluate(r"""(planType) => {
        function clickElement(el) {
            try {
                el.scrollIntoView({ behavior: 'instant', block: 'center' });
            } catch (e) {}
            el.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true }));
            el.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true }));
            el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
            el.click();
        }

        const modal = document.querySelector(
            '.subscriptionModal-wrapper, [class*="subscriptionModal"], [class*="pricingModal"], ' +
            '[class*="vip-modal"], [class*="vipModal"], [role="dialog"], .lv-modal, .lv-modal-content'
        );
        if (!modal) return { clicked: false, count: 0, reason: "modal_not_found" };

        function isUpgradeText(t) {
            return /upgrade|tingkatkan|coba|trial|uji\s*coba|start|mulai|get\s*pro|join\s*pro|beli|buy|berlangganan|subscribe|klaim|claim|pilih|choose|lanjutkan|continue/i.test(t);
        }

        function isExcludedText(t) {
            return /current plan|paket saat ini|take a look|got it|skip|mengerti|cancel|batal|close/i.test(t);
        }

        let target = null;
        let method = "";

        // 0. Highest priority: explicit button with trial / 7-day / coba gratis text
        const explicitTrialBtn = Array.from(modal.querySelectorAll('button, [role="button"], a, div')).find(b => {
            const t = (b.innerText || b.textContent || '').trim().toLowerCase();
            const r = b.getBoundingClientRect();
            return r.width > 35 && r.height > 20 && (
                t.includes('trial') || t.includes('uji coba') || t.includes('coba gratis') ||
                t.includes('7-day') || t.includes('7 hari') || t.includes('free trial')
            ) && !isExcludedText(t);
        });
        if (explicitTrialBtn) {
            target = explicitTrialBtn;
            method = "explicit_trial_button";
        }

        // 1. Direct target by CapCut action button class: subscriptionProductSection-actionDark
        if (!target) {
            const darkBtns = Array.from(modal.querySelectorAll('button.subscriptionProductSection-actionDark, [class*="subscriptionProductSection-actionDark"]'));
            if (darkBtns.length > 0) {
                if (planType === 'teams') {
                    target = darkBtns[darkBtns.length - 1];
                    method = "capcut_teams_dark_btn";
                } else {
                    // Pro button is located horizontally around 250px - 650px
                    const proBtn = darkBtns.find(b => {
                        const r = b.getBoundingClientRect();
                        return r.left > 250 && r.left < 650;
                    });
                    target = proBtn || darkBtns[0];
                    method = "capcut_pro_dark_btn";
                }
            }
        }

        // 2. Fallback: CapCut official modal action buttons (filter out 'Current plan' and exclusions)
        if (!target) {
            const rawBtns = Array.from(modal.querySelectorAll('button.subscriptionProductSection-action, button[class*="subscriptionProductSection-action"], .subscriptionProductSection-action'));
            const actionBtns = rawBtns.filter(b => {
                const t = (b.innerText || b.textContent || '').trim().toLowerCase();
                return !isExcludedText(t);
            });

            if (actionBtns.length > 0) {
                if (planType === 'teams') {
                    target = actionBtns[actionBtns.length - 1];
                    method = "capcut_teams_action_button";
                } else {
                    const proBtn = actionBtns.find(b => {
                        const r = b.getBoundingClientRect();
                        return r.left > 250 && r.left < 650;
                    });
                    target = proBtn || actionBtns[0];
                    method = "capcut_pro_action_button";
                }
            }
        }

        // 3. Try finding Pro card specifically
        if (!target) {
            const allEls = Array.from(modal.querySelectorAll('*'));
            const cards = allEls.filter(el => {
                const r = el.getBoundingClientRect();
                const t = (el.innerText || '').toLowerCase();
                return r.height > 100 && r.width > 80 && (t.includes('pro') || t.includes('tahunan') || t.includes('yearly') || t.includes('bulanan') || t.includes('monthly'));
            });

            const proCards = cards.filter(c => {
                const t = (c.innerText || '').toLowerCase();
                return t.includes('pro') && !t.includes('ultra') && !t.includes('team');
            });

            proCards.sort((a, b) => {
                const ra = a.getBoundingClientRect();
                const rb = b.getBoundingClientRect();
                return (ra.width * ra.height) - (rb.width * rb.height);
            });

            for (const card of proCards) {
                const btns = Array.from(card.querySelectorAll('button, [role="button"], a, div')).filter(b => {
                    const r = b.getBoundingClientRect();
                    const t = (b.innerText || '').trim();
                    return !isExcludedText(t) && r.width > 35 && r.height > 20 && (isUpgradeText(t) || b.tagName === 'BUTTON' || b.getAttribute('role') === 'button');
                });
                if (btns.length > 0) {
                    target = btns[0];
                    method = "pro_card_button";
                    break;
                }
            }
        }

        // 4. If not found, look at any upgrade-like button inside modal
        if (!target) {
            const allButtons = Array.from(modal.querySelectorAll('button, [role="button"], a, div')).filter(b => {
                const t = (b.innerText || b.textContent || '').trim();
                const r = b.getBoundingClientRect();
                const isVisible = r.width > 35 && r.height > 20;
                return isVisible && !isExcludedText(t) && isUpgradeText(t) && r.top > 80;
            });
            if (allButtons.length > 0) {
                const proBtn = allButtons.find(b => {
                    const r = b.getBoundingClientRect();
                    return r.left > 250 && r.left < 650;
                });
                target = proBtn || allButtons[0];
                method = "modal_upgrade_button";
            }
        }

        // 5. Fallback: primary button inside modal (only if text is not excluded)
        if (!target) {
            const primaryBtns = Array.from(modal.querySelectorAll('button.lv-btn-primary, button[type="primary"], [class*="primaryButton"], [class*="highlight-btn"]')).filter(b => {
                const t = (b.innerText || '').trim();
                return !isExcludedText(t);
            });
            if (primaryBtns.length > 0) {
                target = primaryBtns[0];
                method = "modal_primary_btn";
            }
        }

        if (target) {
            clickElement(target);
            return { clicked: true, method: method, text: (target.innerText || '').slice(0, 50) };
        }
        return { clicked: false, reason: "no_button_matched" };
    }""", target_plan)

    log(f"[*] status klik paket {target_plan}: {btn_res}")

    # Fallback native click via Playwright locator
    try:
        upg_btn_loc = page.locator(
            ".subscriptionModal-wrapper button:has-text('Upgrade'), "
            ".subscriptionModal-wrapper button:has-text('Tingkatkan'), "
            ".subscriptionModal-wrapper button:has-text('Coba'), "
            ".subscriptionModal-wrapper button:has-text('Start'), "
            ".subscriptionModal-wrapper button:has-text('Trial'), "
            ".subscriptionModal-wrapper button:has-text('Get Pro'), "
            ".subscriptionModal-wrapper button:has-text('Mulai'), "
            ".subscriptionModal-wrapper button.lv-btn-primary"
        ).first
        if upg_btn_loc.is_visible(timeout=1000):
            upg_btn_loc.click(force=True)
    except Exception:
        pass

    # Look for and click secondary checkout / continue / subscribe button if it appears
    _sleep_with_cancel(1.2, stop)
    for _ in range(4):
        _raise_if_cancelled(stop)
        try:
            sec_clicked = page.evaluate("""() => {
                const btns = Array.from(document.querySelectorAll('button, [role="button"], a'));
                const confirmBtn = btns.find(b => {
                    const t = (b.innerText || b.textContent || '').trim().toLowerCase();
                    const r = b.getBoundingClientRect();
                    const isVisible = r.width > 40 && r.height > 20;
                    return isVisible && (
                        t.includes('continue') || t.includes('lanjutkan') ||
                        t.includes('pay') || t.includes('bayar') ||
                        t.includes('subscribe') || t.includes('berlangganan') ||
                        t.includes('checkout')
                    ) && !t.includes('upgrade') && !t.includes('tingkatkan');
                });
                if (confirmBtn) {
                    confirmBtn.click();
                    return { clicked: true, text: confirmBtn.innerText };
                }
                return { clicked: false };
            }""")
            if sec_clicked.get("clicked"):
                log(f"[*] tombol konfirmasi/checkout sekunder diklik: {sec_clicked}")
                break
        except Exception:
            pass
        _sleep_with_cancel(0.8, stop)

    # Wait for payment link / cashier page / new tab
    payment_link = ""
    wait_deadline = time.time() + 30
    while time.time() < wait_deadline:
        _raise_if_cancelled(stop)

        # 1. Check window.__captured_open_urls (hooked window.open popups)
        try:
            hooked_urls = page.evaluate("() => window.__captured_open_urls || []")
            if hooked_urls:
                captured_urls.extend(hooked_urls)
        except Exception:
            pass

        # 2. Check all open pages and tabs in context (popup window from window.open)
        all_pages = list(opened_pages) + [p for p in context.pages if p not in opened_pages]
        for p in all_pages:
            try:
                p.wait_for_load_state("domcontentloaded", timeout=1500)
            except Exception:
                pass
            u = p.url
            if u and u != "about:blank":
                captured_urls.append(u)
            try:
                for frame in p.frames:
                    fu = frame.url
                    if fu and any(k in fu.lower() for k in ["pipopay", "cashier", "checkout", "agreement-cashier"]):
                        captured_urls.append(fu)
            except Exception:
                pass

        # 3. Check if current page redirected
        curr = page.url
        if any(k in curr.lower() for k in ["pipopay", "checkout", "cashier", "agreement-cashier"]):
            captured_urls.append(curr)

        # 4. Check DOM for iframes and links
        try:
            dom_items = page.evaluate("""() => {
                const results = [];
                for (const f of document.querySelectorAll('iframe')) {
                    const src = f.src || f.getAttribute('src') || '';
                    if (src && /pipopay|cashier|checkout|agreement-cashier/i.test(src)) results.push(src);
                }
                for (const a of document.querySelectorAll('a[href]')) {
                    const h = a.href || '';
                    if (h && /pipopay|cashier|checkout|agreement-cashier/i.test(h)) results.push(h);
                }
                return results;
            }""")
            if dom_items:
                captured_urls.extend(dom_items)
        except Exception:
            pass

        best_link = _clean_payment_url(captured_urls)
        if best_link:
            payment_link = best_link
            break

        _sleep_with_cancel(0.8, stop)

    if payment_link:
        log(f"[+] [PAYMENT ] Link pembayaran didapatkan: {payment_link}")
    else:
        log("[!] tidak dapat menangkap link pembayaran")

    _sleep_with_cancel(1.5, stop)
    return promo_info, payment_link


def _run_signup(
    cfg: Config,
    password: str,
    mail,
    provider: str,
    pending: dict,
    log,
    stop,
    out_file: Optional[Path] = None,
    check_trial: bool = True,
    only_7days: bool = True,
) -> tuple[str, str, str]:
    """Run full CapCut sign-up flow. Returns (full_name, promo_info, payment_link)."""
    if Camoufox is None:
        raise RuntimeError("camoufox is not installed; please run install.bat or pip install -r requirements.txt")

    full_name = getattr(cfg, "profile_name", "") or generate_full_name()
    opts = _browser_ctx_options(cfg, log=log)
    signup_mode = (getattr(cfg, "signup_mode", "email") or "email").strip().lower()

    with Camoufox(**opts) as browser:
        context, page = _context_and_page(browser)
        page.set_default_timeout(25000)

        if "email" not in pending:
            pending["email"], pending["order_id"] = mail.create_mailbox()
            log(f"[*] mailbox: {pending['email']} ({provider})")
        email = pending["email"]

        if signup_mode == "tiktok":
            # 1. Register TikTok Account first
            log("[>] [BRIDGE   ] Mode: TikTok Bridge (Daftar TikTok -> Auto-Login CapCut via SSO)")
            _register_tiktok_account(
                page, mail, email, password, pending["order_id"], cfg, log, stop=stop
            )
            # 2. Login to CapCut via TikTok SSO
            _login_capcut_via_tiktok(context, page, log, stop=stop)
        else:
            # Direct CapCut email registration
            log("[>] [DIRECT   ] Mode: Registrasi Email Langsung CapCut")
            _open_capcut_signup(page, log, stop=stop)

            log(f"[*] submitting email: {email}")
            _fill_capcut_email(page, email, log, stop=stop)

            log(f"[*] submitting password...")
            _fill_capcut_password(page, password, log, stop=stop)

            _fill_capcut_birthday(page, log, stop=stop)

            _enter_capcut_otp(page, mail, email, pending["order_id"], cfg, log, stop=stop)

        _handle_capcut_onboarding(page, log, stop=stop)

        cookies = [c['name'] for c in context.cookies() if 'capcut' in c.get('domain', '')]
        if len(cookies) > 0:
            log(f"[+] account confirmed on CapCut: {email} (session active)")
        else:
            log(f"[+] account registered: {email}")

        pending["account_created"] = True

        promo_info, payment_link = "", ""
        if check_trial:
            try:
                promo_info, payment_link = _process_capcut_upgrade(
                    context, page, log, stop=stop, only_7days=only_7days
                )
            except Exception as exc:
                log(f"[!] error during upgrade check: {exc}")

        return full_name, promo_info, payment_link


def register_one(
    cfg: Config,
    log: Callable[[str], None],
    cancel_cb: Optional[Callable[[], bool]] = None,
    out_file: Optional[Path] = None,
    check_trial: bool = True,
    only_7days: bool = True,
) -> Optional[str]:
    """Register one CapCut account; returns account line or None."""
    stop = cancel_cb or (lambda: False)

    provider = (getattr(cfg, "mail_provider", "tempmail") or "tempmail").strip().lower()
    if provider in ("tempmail", "yourmail", "your_mail", "temp_email", "zaymail"):
        mail = YourMailClient(
            custom_prefix=getattr(cfg, "yourmail_custom_prefix", "") or getattr(cfg, "tempmail_custom_prefix", "") or getattr(cfg, "zaymail_custom_prefix", "") or "",
            domain=getattr(cfg, "yourmail_domain", "") or getattr(cfg, "tempmail_domain", "") or getattr(cfg, "zaymail_domain", "") or "",
            api_base=getattr(cfg, "yourmail_api_url", "") or getattr(cfg, "tempmail_api_url", "") or "",
        )
    elif provider == "litensi":
        mail = LitensiClient(
            api_id=cfg.litensi_api_id,
            api_key=cfg.litensi_api_key,
            site=getattr(cfg, "litensi_site", "") or "capcut.com",
            zone=cfg.litensi_zone,
        )
    elif provider in ("gmail", "gmail_dot"):
        mail = GmailDotClient(
            address=cfg.gmail_address,
            app_password=cfg.gmail_app_password,
        )
    elif provider == "mailcx":
        mail = MailCxClient(domain=cfg.mailcx_domain)
    else:
        mail = YourMailClient(
            custom_prefix=getattr(cfg, "yourmail_custom_prefix", "") or getattr(cfg, "tempmail_custom_prefix", "") or getattr(cfg, "zaymail_custom_prefix", "") or "",
            domain=getattr(cfg, "yourmail_domain", "") or getattr(cfg, "tempmail_domain", "") or getattr(cfg, "zaymail_domain", "") or "",
            api_base=getattr(cfg, "yourmail_api_url", "") or getattr(cfg, "tempmail_api_url", "") or "",
        )

    pending: dict = {}
    succeeded = False
    try:
        password = generate_password()
        full_name, promo_info, payment_link = _run_signup(
            cfg, password, mail, provider, pending, log, stop, out_file=out_file,
            check_trial=check_trial, only_7days=only_7days,
        )
        succeeded = True
        email = pending["email"]

        if not check_trial:
            final_line = f"{email}|{password}"
            _record_account(out_file, final_line, log=log)
            log(f"[+] [REGIST ONLY] Akun {email} berhasil dibuat & disimpan ke {out_file.name if out_file else 'accounts'}.")
            return final_line

        if payment_link:
            succeeded = True
            final_line = f"{email}|{password}|{payment_link}"
            _record_account(out_file, final_line, log=log)
            log(f"[+] [{promo_info or 'TRIAL 7 HARI'}] Link Payment: {payment_link}")
            return final_line
        else:
            # Akun dibuat tetapi tidak ada promo trial 7 hari / diskon
            no_promo_file = ACCOUNTS_DIR / "capcut_accounts_no_promo.txt"
            _record_account(no_promo_file, f"{email}|{password}", log=None)
            log(f"[*] Akun {email} disimpan ke capcut_accounts_no_promo.txt (tanpa promo / trial).")
            return None
    except (KeyboardInterrupt, SystemExit):
        raise
    except RegistrationCancelled:
        if pending.get("account_created"):
            succeeded = True
            email = pending["email"]
            final_line = f"{email}|{password}"
            _record_account(out_file, final_line, log=log)
            return final_line
        raise
    except MailboxCancelled:
        raise RegistrationCancelled("cancelled while waiting for mail")
    except MailboxTimeoutError as exc:
        log(f"[-] account failed: mailbox timeout ({exc}); continuing with next account")
        return None
    except (MailCxError, LitensiError, GmailDotError, YourMailError) as exc:
        log(f"[!] mail provider error, aborting: {exc}")
        raise
    except Exception as exc:
        if pending.get("account_created"):
            succeeded = True
            email = pending["email"]
            final_line = f"{email}|{password}"
            _record_account(out_file, final_line, log=log)
            return final_line
        log(f"[-] account failed: {exc}")
        return None
    finally:
        order_id = pending.get("order_id")
        if provider == "litensi" and order_id is not None:
            if succeeded or pending.get("account_created"):
                try:
                    mail.mark_success(order_id)
                except Exception:
                    pass
            else:
                try:
                    mail.set_status(order_id, "CANCELED")
                except Exception:
                    pass


def run_job(
    cfg: Config,
    cancel_cb: Optional[Callable[[], bool]] = None,
    log: Optional[Callable[[str], None]] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    check_trial: bool = True,
    only_7days: bool = True,
) -> tuple[int, int, Path]:
    """Register CapCut accounts; returns (ok, fail, output_file)."""
    if log is None:
        def _default_log(msg: str) -> None:
            text = f"[{_now()}] {msg}"
            try:
                print(text)
            except UnicodeEncodeError:
                enc = getattr(sys.stdout, "encoding", None) or "ascii"
                print(text.encode(enc, errors="replace").decode(enc, errors="replace"))
        log = _default_log

    stop = cancel_cb or (lambda: False)

    def _emit_progress(ok_count: int, fail_count: int) -> None:
        if progress_cb is None:
            return
        try:
            progress_cb(ok_count, fail_count)
        except Exception:
            pass

    ACCOUNTS_DIR.mkdir(parents=True, exist_ok=True)
    out = ACCOUNTS_DIR / f"capcut_accounts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    target_count = cfg.register_count
    ok = fail = attempt = 0
    max_attempts = max(target_count * 20, 50)
    provider = (getattr(cfg, "mail_provider", "tempmail") or "tempmail").strip().lower()

    mode_label = "Regist + Cek Trial (7 Hari)" if check_trial else "Regist Doang"
    log(f"[*] capcut-regkit | engine=Camoufox (Firefox anti-detect) | mail_provider={provider} "
        f"| mode={mode_label} | headless={cfg.headless} | target={target_count} akun | output={out.name}")
    _emit_progress(ok, fail)

    try:
        while ok < target_count and attempt < max_attempts:
            if stop():
                break
            attempt += 1
            log(f"--- [AKUN {ok + 1}/{target_count}] (Percobaan ke-{attempt}) ---")
            line = None
            try:
                line = register_one(
                    cfg, log, stop, out_file=out,
                    check_trial=check_trial, only_7days=only_7days
                )
            except KeyboardInterrupt:
                raise
            except RegistrationCancelled:
                log("[!] stop requested — browser flow cancelled")
                break
            except (MailCxError, LitensiError, GmailDotError, YourMailError) as exc:
                log(f"[!] mail provider error, aborting: {exc}")
                break

            if line:
                ok += 1
                acc_label = "Akun promo trial" if check_trial else "Akun"
                log(f"[+] {acc_label} #{ok} berhasil disimpan ke {out.name}")
            else:
                fail += 1
                if check_trial:
                    log("[*] Tidak ada promo trial 7 hari pada akun ini. Lanjut membuat akun baru...")
                else:
                    log("[-] Gagal membuat akun. Mencoba lagi...")

            log(f"[*] stats: OK {ok}/{target_count} (percobaan: {attempt})")
            _emit_progress(ok, fail)

            if stop():
                log("[!] stop requested — job ended cleanly")
                break
            if ok < target_count and not stop():
                _sleep_with_cancel(cfg.delay_sec, stop)
    except RegistrationCancelled:
        log("[!] stop requested — job ended cleanly")
    finally:
        _stop_proxy_bridge()
        log(f"[*] done: OK {ok} | FAIL {fail}")
        _emit_progress(ok, fail)

    return ok, fail, out


def _login_capcut_direct(page, email: str, password: str, log, stop=None, attempts: int = 2) -> bool:
    """Login directly to CapCut using email and password."""
    for attempt in range(1, attempts + 1):
        _raise_if_cancelled(stop)
        log(f"[*] membuka halaman login CapCut untuk {email} (percobaan {attempt}/{attempts})...")
        try:
            page.goto("https://www.capcut.com/login", wait_until="domcontentloaded", timeout=45000)
            _sleep_with_cancel(2.5, stop)

            # Accept cookies / privacy banners
            try:
                cookie_btn = page.locator(
                    "button:has-text('Accept all cookies'), button:has-text('Terima semua cookie'), "
                    "button:has-text('Accept'), button:has-text('Terima'), "
                    "button:has-text('Agree'), button:has-text('Setuju'), "
                    "[aria-label='Close'], button.agree-btn"
                ).first
                if cookie_btn.is_visible(timeout=2000):
                    cookie_btn.click()
                    _sleep_with_cancel(0.5, stop)
            except Exception:
                pass

            # Check if session is already active
            if "my-edit" in page.url.lower() or "workspace" in page.url.lower():
                log(f"[+] sesi login CapCut sudah aktif untuk {email}!")
                return True

            # Wait for login options or email input to appear
            try:
                page.wait_for_selector(
                    ".lv_third_part_sign_in_expand-wrapper, .lv-account-login-form-main-field, "
                    "[class*='sign_in-container'], input[type='email'], input[name='username']",
                    timeout=20000
                )
            except Exception:
                pass

            # If email input is not already visible, click 'Continue with email'
            email_inp = page.locator(
                "input[type='email'], input[name='username'], input[placeholder*='email'], input[placeholder*='Email']"
            ).first
            if not email_inp.is_visible(timeout=2000):
                # Try clicking via JS DOM first
                clicked = page.evaluate("""() => {
                    const newBtn = document.querySelector('.lv_third_part_sign_in_expand_new-button, [class*="expand_new-button"]');
                    if (newBtn) {
                        newBtn.click();
                        return true;
                    }
                    const els = Array.from(document.querySelectorAll('.lv_third_part_sign_in_expand-wrapper *, .lv_third_part_sign_in_expand-label, .lv-account-login-form-main-field *, [class*="sign_in"] *, [class*="third_part"] *, button, div, span'));
                    for (const el of els) {
                        const t = (el.innerText || '').toLowerCase().trim();
                        if ((t === 'continue with email' || t === 'lanjutkan dengan email' || t.includes('email') || t.includes('surel')) && t.length < 40) {
                            const btn = el.closest('.lv_third_part_sign_in_expand_new-button, .lv_third_part_sign_in_expand-button, .lv_third_part_sign_in_expand-item, [role="button"], button, div') || el;
                            btn.click();
                            return true;
                        }
                    }
                    return false;
                }""")
                if not clicked:
                    try:
                        email_btn = page.locator(
                            ".lv_third_part_sign_in_expand_new-button, "
                            "span.lv_third_part_sign_in_expand-label:has-text('email'), "
                            "span.lv_third_part_sign_in_expand-label:has-text('Email'), "
                            "[class*='lv_third_part_sign_in']:has-text('email'), "
                            "[class*='lv_third_part_sign_in']:has-text('Email'), "
                            "div[class*='sign_in']:has-text('email'), "
                            "button:has-text('email'), button:has-text('Email')"
                        ).first
                        if email_btn.is_visible(timeout=2500):
                            email_btn.click(timeout=3000, force=True)
                    except Exception:
                        pass
                _sleep_with_cancel(1.5, stop)

            # Input Email with robust retry if container is slow to animate
            for _ in range(3):
                try:
                    email_inp.wait_for(state="visible", timeout=4000)
                    break
                except Exception:
                    page.evaluate("""() => {
                        const all = Array.from(document.querySelectorAll('[class*="third_part"] *, [class*="sign_in"] *, button, div'));
                        for (const el of all) {
                            const t = (el.innerText || '').toLowerCase().trim();
                            if ((t === 'continue with email' || t === 'lanjutkan dengan email' || t.includes('email')) && t.length < 35) {
                                (el.closest('[role="button"], button, div') || el).click();
                                break;
                            }
                        }
                    }""")
                    _sleep_with_cancel(1.0, stop)

            email_inp.wait_for(state="visible", timeout=10000)
            try:
                email_inp.focus()
            except Exception:
                email_inp.evaluate("el => el.focus()")
            email_inp.fill(email)
            _sleep_with_cancel(0.6, stop)

            # Click Continue / Lanjutkan
            try:
                cont_btn = page.locator(
                    "button:has-text('Lanjutkan'), button:has-text('Continue'), "
                    "div[role='button']:has-text('Lanjutkan'), div[role='button']:has-text('Continue')"
                ).first
                if cont_btn.is_visible(timeout=2500):
                    cont_btn.click(timeout=3000)
                else:
                    email_inp.press("Enter")
            except Exception:
                try:
                    email_inp.press("Enter")
                except Exception:
                    pass
            _sleep_with_cancel(2.0, stop)
            _wait_for_captcha_if_any(page, log, stop=stop, timeout=20)

            # Input Password
            pwd_inp = page.locator(
                "input[type='password'], input[name='password'], input[placeholder*='password'], input[placeholder*='sandi']"
            ).first
            pwd_inp.wait_for(state="visible", timeout=12000)
            try:
                pwd_inp.focus()
            except Exception:
                pwd_inp.evaluate("el => el.focus()")
            pwd_inp.fill(password)
            _sleep_with_cancel(0.6, stop)

            # Click Masuk / Log in / Sign in
            login_btn = page.locator(
                ".lv_sign_in_panel_wide-sign-in-button, .lv_sign_in_panel_wide-primary-button, "
                "button:has-text('Sign in'), button:has-text('Masuk'), button:has-text('Log in'), "
                "div[role='button']:has-text('Sign in'), div[role='button']:has-text('Masuk'), div[role='button']:has-text('Log in')"
            ).first
            try:
                login_btn.click(timeout=3000)
            except Exception:
                try:
                    login_btn.click(timeout=2000, force=True)
                except Exception:
                    pass
            _sleep_with_cancel(2.5, stop)
            _wait_for_captcha_if_any(page, log, stop=stop, timeout=20)

            # Check for error messages or success redirect
            deadline = time.time() + 20
            while time.time() < deadline:
                _raise_if_cancelled(stop)
                curr_url = page.url.lower()
                if "my-edit" in curr_url or "workspace" in curr_url or "home" in curr_url:
                    log(f"[+] login berhasil ke CapCut untuk {email}!")
                    return True

                err_text = page.evaluate("""() => {
                    const err = document.querySelector('.lv-form-explain, [class*="error"], [role="alert"]');
                    return err ? (err.innerText || err.textContent || '').trim() : '';
                }""")
                if err_text and any(k in err_text.lower() for k in ["salah", "incorrect", "invalid", "tidak terdaftar", "does not exist"]):
                    log(f"[-] login gagal untuk {email}: {err_text}")
                    return False

                _sleep_with_cancel(1.0, stop)

            if "my-edit" in page.url.lower() or "workspace" in page.url.lower():
                return True
        except Exception as exc:
            log(f"[!] kesalahan saat proses login {email} ({exc}); mencoba ulang...")
            _sleep_with_cancel(2.0, stop)

    return "my-edit" in page.url.lower() or "workspace" in page.url.lower()


def _login_capcut_google(page, context, email: str, password: str, log, stop=None, attempts: int = 2) -> bool:
    """Login to CapCut using 'Continue with Google' OAuth SSO."""
    for attempt in range(1, attempts + 1):
        _raise_if_cancelled(stop)
        log(f"[*] membuka halaman login CapCut untuk Google SSO: {email} (percobaan {attempt}/{attempts})...")
        try:
            page.goto("https://www.capcut.com/login", wait_until="domcontentloaded", timeout=45000)
            _sleep_with_cancel(2.5, stop)

            # Accept cookies
            try:
                cookie_btn = page.locator(
                    "button:has-text('Accept all cookies'), button:has-text('Terima semua cookie'), "
                    "button:has-text('Accept'), button:has-text('Agree'), [aria-label='Close'], button.agree-btn"
                ).first
                if cookie_btn.is_visible(timeout=1500):
                    cookie_btn.click()
                    _sleep_with_cancel(0.5, stop)
            except Exception:
                pass

            if "my-edit" in page.url.lower() or "workspace" in page.url.lower():
                log(f"[+] sesi login CapCut sudah aktif untuk {email}!")
                return True

            # Wait for third-party sign-in buttons
            try:
                page.wait_for_selector(".lv_third_part_sign_in_expand-wrapper, [class*='sign_in'], button", timeout=15000)
            except Exception:
                pass

            # Click "Continue with Google"
            log("[*] mencari dan mengklik tombol 'Continue with Google'...")
            google_page = None
            google_btn = page.locator(
                ".lv_google_sign_in_btn-expand-hit-area, .nsm7Bb-HzV7m-LgbsSe, "
                "[class*='google_sign_in_btn'], button:has-text('Google'), "
                "[aria-label*='Google' i], [class*='google' i]"
            ).first

            try:
                if google_btn.is_visible(timeout=5000):
                    google_btn.scroll_into_view_if_needed()
                    with context.expect_page(timeout=10000) as p_info:
                        google_btn.click()
                    google_page = p_info.value
            except Exception as exc:
                log(f"[i] catatan klik Google Playwright: {exc}")

            if not google_page:
                for p in context.pages:
                    if "google.com" in p.url.lower():
                        google_page = p
                        break
                if not google_page and "google.com" in page.url.lower():
                    google_page = page

            if not google_page:
                # Try fallback click via mouse coordinates
                try:
                    box = google_btn.bounding_box()
                    if box:
                        with context.expect_page(timeout=8000) as p_info:
                            page.mouse.click(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
                        google_page = p_info.value
                except Exception:
                    pass

            if not google_page:
                for p in context.pages:
                    if "google.com" in p.url.lower():
                        google_page = p
                        break
                if not google_page and "google.com" in page.url.lower():
                    google_page = page

            if not google_page:
                log("[!] jendela login Google tidak terbuka, mencoba lagi...")
                continue

            log(f"[*] jendela login Google terdeteksi, memproses autentikasi untuk {email}...")
            _sleep_with_cancel(2.0, stop)

            # 1. Fill Google Email
            try:
                google_page.wait_for_selector("input[type='email'], input#identifierId, input[name='identifier']", timeout=20000)
                email_inp = google_page.locator("input[type='email'], input#identifierId, input[name='identifier']").first
                email_inp.fill(email)
                _sleep_with_cancel(0.5, stop)
                next_btn = google_page.locator("#identifierNext, button:has-text('Next'), button:has-text('Berikutnya'), [role='button']:has-text('Next')").first
                next_btn.click()
                log("[*] email Google dimasukkan, menunggu form password...")
                _sleep_with_cancel(3.0, stop)
            except Exception as e:
                log(f"[i] catatan input email Google: {e}")

            # 2. Fill Google Password
            try:
                google_page.wait_for_selector("input[type='password'], input[name='Passwd'], input[name='password']", timeout=20000)
                pwd_inp = google_page.locator("input[type='password'], input[name='Passwd'], input[name='password']").first
                pwd_inp.fill(password)
                _sleep_with_cancel(0.5, stop)
                pwd_next = google_page.locator("#passwordNext, button:has-text('Next'), button:has-text('Berikutnya'), [role='button']:has-text('Next')").first
                pwd_next.click()
                log("[*] password Google dimasukkan, memproses login...")
                _sleep_with_cancel(3.5, stop)
            except Exception as e:
                log(f"[i] catatan input password Google: {e}")

            # 3. Dismiss any Google security/recovery/workspace confirmation ("I understand", "Lanjutkan", "Confirm")
            log("[*] memproses layar konfirmasi / izin Google...")
            for _ in range(12):
                _sleep_with_cancel(1.5, stop)
                try:
                    if google_page != page and google_page.is_closed():
                        break
                except Exception:
                    break

                try:
                    # Scroll down button on Google Workspace education / consent screens
                    google_page.evaluate("""() => {
                        window.scrollTo(0, document.body ? document.body.scrollHeight : 1000);
                        const scrollBtn = document.querySelector('button[aria-label*="scroll" i], button[aria-label*="down" i], button[aria-label*="bawah" i]');
                        if (scrollBtn) scrollBtn.click();
                        const all = Array.from(document.querySelectorAll('button, [role="button"], a, input[type="submit"]'));
                        const agreeBtn = all.find(b => {
                            const t = (b.innerText || b.textContent || b.getAttribute('aria-label') || '').toLowerCase().trim();
                            return t === 'i understand' || t === 'saya mengerti' ||
                                   t === 'continue' || t === 'lanjutkan' ||
                                   t === 'confirm' || t === 'konfirmasi' ||
                                   t === 'accept' || t === 'terima' ||
                                   t === 'allow' || t === 'izinkan' ||
                                   t === 'agree' || t === 'setuju' ||
                                   t === 'saya setuju' || t === 'i agree' ||
                                   t === 'not now' || t === 'jangan sekarang';
                        });
                        if (agreeBtn) agreeBtn.click();
                    }""")
                except Exception:
                    pass

                # Check if session cookie already arrived in CapCut
                cookies = [c['name'] for c in context.cookies() if 'capcut' in c.get('domain', '')]
                if any(k in str(cookies).lower() for k in ["passport", "session", "uid", "login_status"]):
                    log(f"[+] login Google CapCut terkonfirmasi via cookie sesi aktif!")
                    return True

            # 4. Wait for redirect back to CapCut
            log("[*] menunggu otorisasi Google selesai dan dialihkan ke CapCut...")
            oauth_deadline = time.time() + 45
            first_snap = False
            while time.time() < oauth_deadline:
                _raise_if_cancelled(stop)

                # If popup was closed or completed
                is_closed = True
                try:
                    is_closed = (google_page != page and google_page.is_closed())
                except Exception:
                    is_closed = True

                if is_closed:
                    log("[i] Google popup window closed.")
                    break

                if google_page != page and not is_closed and not first_snap:
                    try:
                        time.sleep(3)
                        google_page.screenshot(path="google_auth_popup.png")
                        log(f"[i] Google popup URL: {google_page.url}")
                        log(f"[i] Google popup text: {google_page.evaluate('() => document.body ? document.body.innerText : \"\"')[:300].replace(chr(10), ' ')}")
                        first_snap = True
                    except Exception as e:
                        log(f"[i] error snapping google page: {e}")

                # Check if main page is already on dashboard
                curr_u = page.url.lower()
                if "my-edit" in curr_u or "workspace" in curr_u:
                    log(f"[+] login Google CapCut berhasil untuk {email}!")
                    return True

                # Check cookies for active session
                cookies = [c['name'] for c in context.cookies() if 'capcut' in c.get('domain', '')]
                if any(k in str(cookies).lower() for k in ["passport", "session", "uid", "login_status"]):
                    log(f"[+] login Google CapCut terkonfirmasi via cookie sesi aktif!")
                    return True

                _sleep_with_cancel(1.0, stop)

            try:
                if google_page != page and not google_page.is_closed():
                    google_page.screenshot(path="google_auth_popup_end.png")
                    log(f"[i] Google popup END URL: {google_page.url}")
                    log(f"[i] Google popup END text: {google_page.evaluate('() => document.body ? document.body.innerText : \"\"')[:500].replace(chr(10), ' ')}")
            except Exception:
                pass

            # Try navigating to my-edit to verify session
            _sleep_with_cancel(2.0, stop)
            try:
                page.goto("https://www.capcut.com/my-edit", wait_until="domcontentloaded", timeout=20000)
                _sleep_with_cancel(2.5, stop)
            except Exception:
                pass

            if "my-edit" in page.url.lower() or "workspace" in page.url.lower():
                log(f"[+] login Google CapCut berhasil untuk {email}!")
                return True

            cookies = [c['name'] for c in context.cookies() if 'capcut' in c.get('domain', '')]
            if any(k in str(cookies).lower() for k in ["passport", "session", "uid", "login_status"]):
                log(f"[+] login Google CapCut terkonfirmasi via cookie sesi aktif!")
                return True

        except Exception as exc:
            log(f"[!] error saat login Google untuk {email}: {exc}")
            _sleep_with_cancel(2.0, stop)

    return "my-edit" in page.url.lower() or "workspace" in page.url.lower()


def check_existing_account_trial(
    email: str,
    password: str,
    cfg: Config,
    log: Callable[[str], None],
    stop: Optional[Callable[[], bool]] = None,
    only_7days: bool = True,
    use_google: bool = False,
) -> dict:
    """Check if an existing CapCut account has a 7-day trial and retrieve payment link."""
    stop_fn = stop or (lambda: False)
    if Camoufox is None:
        raise RuntimeError("camoufox is not installed; please run install.bat")

    result = {
        "email": email,
        "password": password,
        "status": "error",
        "trial_info": "",
        "payment_link": "",
        "error": "",
    }

    opts = _browser_ctx_options(cfg, log=log)
    try:
        with Camoufox(**opts) as browser:
            context, page = _context_and_page(browser)
            page.set_default_timeout(25000)

            # Jika use_google atau email gmail/google workspace, gunakan login Google (Continue with Google)
            is_gmail = use_google or any(email.lower().strip().endswith(d) for d in ["@gmail.com", "@googlemail.com", "@dusasla.com"])
            if is_gmail:
                log(f"[*] akun Google SSO terdeteksi ({email}): login menggunakan metode Google (Continue with Google)...")
                logged_in = _login_capcut_google(page, context, email, password, log, stop=stop_fn, attempts=2)
            else:
                logged_in = _login_capcut_direct(page, email, password, log, stop=stop_fn)
                if not logged_in:
                    log(f"[*] direct login gagal, mencoba fallback login Google SSO untuk {email}...")
                    logged_in = _login_capcut_google(page, context, email, password, log, stop=stop_fn, attempts=1)

            if not logged_in:
                result["status"] = "login_failed"
                result["error"] = "Gagal login Google (jendela login tidak terbuka / password salah / verifikasi dibatalkan)" if is_gmail else "Gagal login (password salah / captcha / akun tidak ditemukan)"
                return result

            _handle_capcut_onboarding(page, log, stop=stop_fn)

            promo_info, payment_link = _process_capcut_upgrade(
                context, page, log, stop=stop_fn, only_7days=only_7days
            )

            if payment_link:
                result["status"] = "trial_found"
                result["trial_info"] = promo_info or "Promo / Diskon CapCut"
                result["payment_link"] = payment_link
                log(f"[+] [SUKSES PROMO] {email} mendapatkan promo ({promo_info})! Link Pipopay: {payment_link}")
            else:
                result["status"] = "no_trial"
                result["error"] = "Tidak ditemukan promo Trial 7 Hari (Rp0) atau diskon"
                log(f"[-] [NO PROMO] {email} tidak memiliki Trial / diskon.")

            return result
    except RegistrationCancelled:
        result["error"] = "Dibatalkan oleh pengguna"
        return result
    except Exception as exc:
        log(f"[!] error checking account {email}: {exc}")
        result["error"] = str(exc)
        return result


def run_trial_checker_job(
    accounts: list[tuple[str, str]],
    cfg: Config,
    cancel_cb: Optional[Callable[[], bool]] = None,
    log: Optional[Callable[[str], None]] = None,
    progress_cb: Optional[Callable[[int, int, list], None]] = None,
    use_google: bool = False,
) -> tuple[int, int, Path, list[dict]]:
    """Check a list of existing CapCut accounts for 7-day trials."""
    if log is None:
        def _default_log(msg: str) -> None:
            text = f"[{_now()}] {msg}"
            try:
                print(text)
            except Exception:
                pass
        log = _default_log

    stop = cancel_cb or (lambda: False)
    ACCOUNTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_trial = ACCOUNTS_DIR / f"capcut_trial_7hari_{ts}.txt"
    out_no_promo = ACCOUNTS_DIR / f"capcut_trial_no_promo_{ts}.txt"

    total = len(accounts)
    ok = 0
    fail = 0
    results: list[dict] = []

    log(f"[*] Memulai Cek Trial untuk {total} akun...")

    for idx, (email, password) in enumerate(accounts, start=1):
        if stop():
            log("[!] Penghentian diminta oleh pengguna.")
            break

        log(f"--- [CEK AKUN {idx}/{total}] {email} ---")
        res = check_existing_account_trial(email, password, cfg, log, stop=stop, only_7days=False, use_google=use_google)
        results.append(res)

        if res["status"] == "trial_found":
            ok += 1
            line = f"{email}|{password}|{res['payment_link']}"
            _record_account(out_trial, line, log=None)
            log(f"[+] Akun {email} disimpan ke {out_trial.name}")
        else:
            fail += 1
            line = f"{email}|{password}"
            _record_account(out_no_promo, line, log=None)
            log(f"[-] Akun {email} disimpan ke {out_no_promo.name}")

        if progress_cb:
            try:
                progress_cb(ok, fail, results)
            except Exception:
                pass

        if idx < total and not stop():
            _sleep_with_cancel(cfg.delay_sec, stop)

    _stop_proxy_bridge()
    log(f"[*] Cek Trial selesai: {ok} memiliki Trial 7 Hari | {fail} tidak ada trial / gagal.")
    return ok, fail, out_trial, results
