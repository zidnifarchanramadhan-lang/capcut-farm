"""Profile helpers: passwords, GitHub usernames, OTP extraction."""
from __future__ import annotations

import re
import secrets
import string
from typing import Any

_LOWER = string.ascii_lowercase
_UPPER = string.ascii_uppercase
_DIGITS = string.digits
_SYMBOLS = "!@#$%^&*"

_WORDS = [
    "novak", "rava", "kelby", "orin", "zephyr", "marlow", "quill", "sable",
    "tenzin", "fable", "gable", "harlow", "irwin", "jasper", "keaton",
    "landry", "moss", "nolan", "otter", "pascal", "quinn", "rivers", "silas",
    "tobin", "ulric", "vance", "wren", "xander", "yates", "zane",
]

_USERNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9]|-(?!-))*[a-z0-9]$")


def generate_password(length: int = 14) -> str:
    """Random password that meets TikTok/CapCut rules (letters, numbers, special characters, 8-20 chars)."""
    charset = _LOWER + _UPPER + _DIGITS + _SYMBOLS
    while True:
        pw = "".join(secrets.choice(charset) for _ in range(length))
        if (
            any(c in _LOWER for c in pw)
            and any(c in _UPPER for c in pw)
            and any(c in _DIGITS for c in pw)
            and any(c in _SYMBOLS for c in pw)
        ):
            return pw


def generate_username() -> str:
    """GitHub-safe username: [a-z0-9-], no consecutive hyphens, <= 39 chars."""
    suffix = "".join(secrets.choice(_LOWER + _DIGITS) for _ in range(6))
    return f"{secrets.choice(_WORDS)}{suffix}"


def username_from_email(email: str, suffix: str = "") -> str:
    """Derive a GitHub username from the mailbox local-part.

    myname123@mail.example.com -> 'myname123'
    Falls back to a random username when the local-part is unusable.
    A short random suffix can be appended when the name is taken.
    """
    local = (email or "").split("@", 1)[0].strip().lower()
    local = re.sub(r"[^a-z0-9-]", "", local)
    local = local.strip("-").replace("--", "-")
    if not is_valid_username(local):
        return generate_username()
    name = (local + suffix)[:39]
    return name if is_valid_username(name) else generate_username()


def is_valid_username(name: str) -> bool:
    return 1 <= len(name) <= 39 and bool(_USERNAME_RE.match(name))


_FIRST_NAMES = [
    "Ahmad", "Budi", "Dewi", "Eko", "Fajar", "Gita", "Hadi", "Indah", "Joko",
    "Kartika", "Lestari", "Muhammad", "Nanda", "Putra", "Rian", "Siti", "Tri",
    "Wahyu", "Yoga", "Zainal", "Alex", "Brian", "David", "Emma", "Grace",
    "James", "Kevin", "Lisa", "Michael", "Sarah"
]

_LAST_NAMES = [
    "Pratama", "Santoso", "Saputra", "Wijaya", "Kusuma", "Hidayat", "Nugroho",
    "Utomo", "Wibowo", "Setiawan", "Permana", "Rahman", "Suryadi", "Batubara",
    "Miller", "Smith", "Johnson", "Williams", "Brown", "Jones", "Davis"
]


def generate_full_name() -> str:
    """Generate a realistic full name for Canva profile."""
    return f"{secrets.choice(_FIRST_NAMES)} {secrets.choice(_LAST_NAMES)}"


def extract_github_code(text: str) -> str | None:
    """Extract OTP code (supports CapCut, Canva 6-digit codes and GitHub 8-digit codes)."""
    if not text:
        return None
    # 0. Check for TikTok specific pattern: "[TikTok] 123456 is your verification code"
    m_tiktok = re.search(r"(?:TikTok.*?|your\s+)verification\s+code\s+(?:is\s+)?[:\s]*(\d{6})", text, re.IGNORECASE)
    if m_tiktok:
        return m_tiktok.group(1)
    m_tiktok2 = re.search(r"\b(\d{6})\s+is\s+your\s+(?:TikTok\s+)?verification\s+code", text, re.IGNORECASE)
    if m_tiktok2:
        return m_tiktok2.group(1)

    # 0b. Check for CapCut specific pattern: "your verification code is 123456"
    m_capcut = re.search(r"(?:CapCut.*?|your\s+)verification\s+code\s+(?:is\s+)?[:\s]*(\d{6})", text, re.IGNORECASE)
    if m_capcut:
        return m_capcut.group(1)

    # 1. Check for Canva specific pattern: "123456 is your Canva code" or "Your Canva code is 123456"
    m_canva = re.search(r"\b(\d{6})\s+is\s+your\s+Canva\s+code", text, re.IGNORECASE)
    if m_canva:
        return m_canva.group(1)
    m_canva2 = re.search(r"Your\s+Canva\s+code\s+is\s+(\d{6})", text, re.IGNORECASE)
    if m_canva2:
        return m_canva2.group(1)
    m_canva3 = re.search(r"Canva\s+code[:\s]+(\d{6})", text, re.IGNORECASE)
    if m_canva3:
        return m_canva3.group(1)

    # 2. Check for 8-digit split format: XXXX-XXXX or XXXX XXXX
    m_split = re.search(r"\b(\d{4})[-\s](\d{4})\b", text)
    if m_split:
        return m_split.group(1) + m_split.group(2)

    # 3. Check for general code patterns
    for pat in (
        r"verification\s+code[:\s]+(\d{4,8})",
        r"your\s+code[:\s]+(\d{4,8})",
        r"enter\s+this\s+code[:\s]+(\d{4,8})",
        r"code[:\s]+(\d{6,8})",
    ):
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(1)

    # 4. Fallback: isolated 6-digit or 8-digit number
    m_iso = re.search(r"\b(\d{6})\b", text)
    if m_iso:
        return m_iso.group(1)
    m_iso8 = re.search(r"\b(\d{8})\b", text)
    if m_iso8:
        return m_iso8.group(1)

    return None

extract_canva_code = extract_github_code
extract_capcut_code = extract_github_code
extract_tiktok_code = extract_github_code


def parse_public_profile(random_user: Any, quote: Any) -> dict[str, str]:
    """Extract public display fields from Random User and ZenQuotes payloads.

    Contact details and generated credentials in the Random User response are
    intentionally ignored.
    """
    try:
        user = random_user["results"][0]
        person = user["name"]
        full_name = " ".join(
            part.strip()
            for part in (person.get("title", ""), person["first"], person["last"])
            if part.strip()
        )
        location = str(user["location"]["country"]).strip()
        bio = str(quote[0]["q"]).strip()
    except (IndexError, KeyError, TypeError, AttributeError) as exc:
        raise ValueError(f"invalid public profile payload: {exc}") from exc
    if not full_name or not location or not bio:
        raise ValueError("public profile payload has an empty required field")
    return {"name": full_name, "location": location, "bio": bio}
