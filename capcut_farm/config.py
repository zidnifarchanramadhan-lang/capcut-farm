"""Configuration loading for CapCut registration toolkit."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    # Mail provider: "tempmail" / "yourmail" (Your Mail / Temp Mail REST API),
    # "gmail_dot" (Gmail aliases via App Password), "mailcx", or "litensi"
    mail_provider: str = "tempmail"  # "tempmail" | "yourmail" | "gmail_dot" | "mailcx" | "litensi"
    # Registration mode: "email" (Direct CapCut email) or "tiktok" (TikTok bridge)
    signup_mode: str = "email"
    # Your Mail / tempmail settings (REST API)
    yourmail_api_url: str = "https://your-api-temp-mail.com/api"
    yourmail_domain: str = ""          # e.g. "yourdomain.com" | "" (auto rotation)
    yourmail_custom_prefix: str = ""   # blank = auto random human names
    # Aliases for backward compatibility
    tempmail_api_url: str = ""
    tempmail_domain: str = ""
    tempmail_custom_prefix: str = ""
    zaymail_domain: str = ""
    zaymail_custom_prefix: str = ""
    # Gmail dot-trick settings (mail_provider == "gmail_dot")
    gmail_address: str = ""           # e.g. "user@gmail.com"
    gmail_app_password: str = ""      # 16-char App Password (not the normal password)
    # Mail.cx temp email settings
    mailcx_domain: str = ""
    # Litensi Mail settings
    litensi_api_id: str = ""
    litensi_api_key: str = ""
    litensi_site: str = "capcut.com"
    litensi_zone: str = ""
    register_count: int = 1
    proxy: str = ""
    proxy_file: str = ""     # proxy pool file in project root (one URL per line); overrides proxy
    headless: bool = False
    delay_sec: float = 5.0
    max_username_tries: int = 6
    otp_timeout_sec: int = 240
    browser_profile_dir: str = ".browser-profile"
    fresh_profile: bool = True
    proxy_hard_block_retries: int = 2
    proxy_rate_limit_retries: int = 2

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        known = set(cls.__dataclass_fields__)
        mapped = {k: v for k, v in data.items() if k in known}
        # Harmonize yourmail / tempmail / zaymail aliases
        if "yourmail_api_url" not in mapped:
            mapped["yourmail_api_url"] = (
                data.get("tempmail_api_url")
                or data.get("api_url")
                or "https://your-api-temp-mail.com/api"
            )
        if not mapped.get("yourmail_domain"):
            mapped["yourmail_domain"] = data.get("tempmail_domain") or data.get("zaymail_domain") or ""
        if not mapped.get("yourmail_custom_prefix"):
            mapped["yourmail_custom_prefix"] = data.get("tempmail_custom_prefix") or data.get("zaymail_custom_prefix") or ""
        return cls(**mapped)


def load_config(path: str | Path) -> Config:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(
            f"config not found: {p} (copy config.example.json to config.json and fill it in)"
        )
    data = json.loads(p.read_text(encoding="utf-8"))
    return Config.from_dict(data)
