#!/usr/bin/env python3
"""CLI entry: automated CapCut sign-up & promo check with Camoufox."""
from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

# Ensure UTF-8 output on Windows console / pipes / redirection
if sys.platform == "win32":
    os.system("")  # Enables ANSI color sequences in Windows cmd & powershell
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

from capcut_farm.config import load_config
from capcut_farm.runner import run_job, silence_playwright_noise

C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_CYAN = "\033[96m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_BLUE = "\033[94m"
C_DIM = "\033[90m"

FARM_LOG_PATH = Path("farm.log")


def _safe_print(text: str) -> None:
    try:
        print(text, flush=True)
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, "encoding", None) or "ascii"
        print(text.encode(enc, errors="replace").decode(enc, errors="replace"), flush=True)


def _write_farm_log(msg: str) -> None:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with FARM_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(f"[{now_str}] {msg}\n")
    except Exception:
        pass


def cli_logger(msg: str) -> None:
    """Format bot logs with clear, colored process indicators in the terminal."""
    _write_farm_log(msg)
    clean = msg.strip()

    m_acc = re.match(r"^---\s*account\s+(\d+)/(\d+)\s*---", clean)
    if m_acc:
        cur, tot = m_acc.group(1), m_acc.group(2)
        _safe_print("")
        _safe_print(f"{C_BLUE}{C_BOLD}{'=' * 60}{C_RESET}")
        _safe_print(f"{C_CYAN}{C_BOLD}>> [PROSES] MEMULAI AKUN {cur} DARI {tot}{C_RESET}")
        _safe_print(f"{C_BLUE}{C_BOLD}{'=' * 60}{C_RESET}")
        return

    if "capcut-regkit | engine=" in clean or "canva-regkit | engine=" in clean or "github-regkit | engine=" in clean:
        _safe_print(f"{C_CYAN}{C_BOLD}[*] [SETUP     ]{C_RESET} Inisialisasi browser Camoufox & mail provider...")
        return

    if "proxy selected:" in clean:
        m = re.search(r"proxy selected:\s*(.+)", clean)
        p = m.group(1) if m else clean
        _safe_print(f"{C_DIM}    [*] [PROXY   ] Menggunakan proxy: {p}{C_RESET}")
        return

    if "[BRIDGE   ]" in clean or "[METODE  ]" in clean:
        _safe_print(f"{C_BLUE}{C_BOLD}[>] [METODE    ]{C_RESET} {clean.split(']', 2)[-1].strip()}")
        return

    if "[TIKTOK 1/4]" in clean:
        _safe_print(f"{C_CYAN}{C_BOLD}[>] [TIKTOK 1/4]{C_RESET} Membuka formulir pendaftaran TikTok...")
        return

    if "[TIKTOK 2/4]" in clean:
        m = re.search(r"pendaftaran:\s*(\S+)", clean)
        em = m.group(1) if m else ""
        _safe_print(f"{C_CYAN}{C_BOLD}[>] [TIKTOK 2/4]{C_RESET} Mengisi email & password TikTok ({em})...")
        return

    if "[TIKTOK 3/4]" in clean:
        _safe_print(f"{C_YELLOW}{C_BOLD}[~] [TIKTOK 3/4]{C_RESET} Menunggu kode OTP verifikasi masuk dari TikTok...")
        return

    if "[TIKTOK 4/4]" in clean:
        _safe_print(f"{C_GREEN}{C_BOLD}[+] [TIKTOK 4/4]{C_RESET} Akun TikTok berhasil dibuat & sesi login aktif!")
        return

    if "[CAPTCHA ]" in clean:
        _safe_print(f"{C_YELLOW}{C_BOLD}[!] [CAPTCHA   ]{C_RESET} {clean.split(']', 2)[-1].strip()}")
        return

    if "[CAPCUT SSO]" in clean:
        _safe_print(f"{C_CYAN}{C_BOLD}[>] [CAPCUT SSO]{C_RESET} {clean.split('[CAPCUT SSO]', 1)[-1].strip()}")
        return

    if "opening https://www.capcut.com" in clean or "opening https://www.canva.com" in clean or "opening https://github.com" in clean:
        _safe_print(f"{C_CYAN}{C_BOLD}[>] [TAHAP 1/5 ]{C_RESET} Membuka website CapCut...")
        return

    if "CapCut signup email form is ready" in clean or "signup email form is ready" in clean:
        _safe_print(f"{C_CYAN}{C_BOLD}[>] [TAHAP 1/5 ]{C_RESET} Formulir pendaftaran CapCut siap!")
        return

    if "mailbox:" in clean:
        m = re.search(r"mailbox:\s*(\S+)", clean)
        email = m.group(1) if m else clean
        _safe_print(f"{C_CYAN}{C_BOLD}[>] [TAHAP 2/5 ]{C_RESET} Email siap: {C_BOLD}{email}{C_RESET}")
        return

    if "submitting email:" in clean:
        m = re.search(r"submitting email:\s*(\S+)", clean)
        em = m.group(1) if m else ""
        _safe_print(f"{C_CYAN}{C_BOLD}[>] [TAHAP 2/5 ]{C_RESET} Mengirim email pendaftaran ({em})...")
        return

    if "submitting password..." in clean:
        _safe_print(f"{C_CYAN}{C_BOLD}[>] [TAHAP 3/5 ]{C_RESET} Mengirim password pendaftaran...")
        return

    if "filling birthday information..." in clean:
        _safe_print(f"{C_CYAN}{C_BOLD}[>] [TAHAP 3/5 ]{C_RESET} Mengisi tanggal lahir...")
        return

    if "waiting for CapCut verification code" in clean or "waiting for Canva verification code" in clean:
        _safe_print(f"{C_YELLOW}{C_BOLD}[~] [TAHAP 4/5 ]{C_RESET} Menunggu kode verifikasi OTP masuk dari CapCut...")
        return

    if "verification code found:" in clean:
        m = re.search(r"code found:\s*(\w+)", clean)
        if m:
            code = m.group(1)
            _safe_print(f"{C_GREEN}{C_BOLD}[+] [TAHAP 5/5 ]{C_RESET} Kode OTP diterima: {C_BOLD}{code}{C_RESET} -> Menginput kode...")
            return

    if "account confirmed on CapCut:" in clean or "account confirmed on Canva:" in clean or "account confirmed on GitHub:" in clean:
        m = re.search(r"account confirmed on (?:CapCut|Canva|GitHub):\s*(.+)", clean)
        info = m.group(1) if m else clean
        _safe_print(f"{C_GREEN}{C_BOLD}[+] [TERDAFTAR ]{C_RESET} Akun CapCut berhasil dibuat: {C_BOLD}{info}{C_RESET}")
        return

    if "[UPGRADE ]" in clean:
        msg_text = clean.split("[UPGRADE ]", 1)[-1].strip()
        _safe_print(f"{C_CYAN}{C_BOLD}[>] [UPGRADE   ]{C_RESET} {msg_text}")
        return

    if "[PROMO   ]" in clean or "[PROMO ]" in clean:
        msg_text = re.sub(r"^(\[[^\]]+\]\s*)+", "", clean).strip()
        _safe_print(f"{C_GREEN}{C_BOLD}[+] [PROMO     ]{C_RESET} {msg_text}")
        return

    if "[PAYMENT ]" in clean:
        link = re.sub(r"^(\[[^\]]+\]\s*)+", "", clean).strip()
        _safe_print(f"{C_GREEN}{C_BOLD}[+] [PAYMENT   ]{C_RESET} {C_CYAN}{link}{C_RESET}")
        return

    if "saved to capcut_accounts_" in clean or "saved to canva_accounts_" in clean or "saved to github_accounts_" in clean:
        m = re.search(r"to\s+(\S+accounts_\S+)", clean)
        fn = m.group(1) if m else "accounts/"
        _safe_print(f"{C_GREEN}{C_BOLD}[+] [TERSIMPAN ]{C_RESET} Kredensial tersimpan di accounts/{fn}")
        return

    if "account recorded to" in clean:
        return

    if "stats: OK" in clean:
        m = re.search(r"OK\s*(\d+)(?:\s*\|\s*FAIL\s*|\s*/\s*)(\d+)", clean)
        if m:
            ok_n, sec_n = m.group(1), m.group(2)
            _safe_print(f"{C_BLUE}{C_BOLD}[=] [STATUS    ]{C_RESET} Berhasil: {C_GREEN}{ok_n}{C_RESET} / {C_CYAN}{sec_n}{C_RESET}")
            return

    if "done: OK" in clean:
        return

    if clean.startswith("[-]"):
        _safe_print(f"{C_RED}{C_BOLD}[-] [GAGAL     ]{C_RESET} {clean[3:].strip()}")
        return

    if clean.startswith("[!]"):
        _safe_print(f"{C_YELLOW}{C_BOLD}[!] [PERINGATAN]{C_RESET} {clean[3:].strip()}")
        return

    if clean.startswith("[+]"):
        _safe_print(f"{C_GREEN}{C_BOLD}[+] [SUKSES    ]{C_RESET} {clean[3:].strip()}")
        return

    # Skip low-level noise in terminal
    if any(k in clean for k in (
        "datadome trust",
        "mailbox cleanup",
        "trust cookie",
        "cloned",
        "login form submitted",
        "post-submit state",
        "verification page",
        "no submit button found",
        "verification code extracted and submitted"
    )):
        return

    if clean.startswith("[i]"):
        _safe_print(f"{C_DIM}    [i] {clean[3:].strip()}{C_RESET}")
        return

    if clean.startswith("[*]"):
        _safe_print(f"{C_DIM}    [*] {clean[3:].strip()}{C_RESET}")
        return

    _safe_print(f"{C_DIM}{clean}{C_RESET}")


def main() -> int:
    silence_playwright_noise()  # hide TargetClosedError spam on browser exit
    ap = argparse.ArgumentParser(
        prog="zayse-capcut-farm",
        description="ZAYSE CAPCUT FARM - Auto-register CapCut accounts (Camoufox + Mail Providers).",
    )
    ap.add_argument("--config", default="config.json", help="path to config json")
    ap.add_argument("--count", type=int, default=None, help="override register_count")
    ap.add_argument("--headless", action="store_true", help="run browsers hidden")
    ap.add_argument("--proxy", default="", help="override proxy, e.g. http://user:pass@host:port")
    ap.add_argument(
        "--mail-provider",
        dest="mail_provider",
        default=None,
        help="override mail provider (tempmail / gmail)",
    )
    ap.add_argument(
        "--signup-mode",
        dest="signup_mode",
        choices=["email", "tiktok", "gmail_manual"],
        default="email",
        help="metode: email (langsung CapCut), tiktok (TikTok Bridge SSO), gmail_manual (akun Gmail manual)",
    )
    ap.add_argument(
        "--mode",
        choices=["regist", "regist_trial", "check_trial"],
        default="regist_trial",
        help="mode: regist (daftar saja), regist_trial (daftar + cek diskon/trial), check_trial (cek diskon/trial akun ada)",
    )
    ap.add_argument(
        "--accounts-file",
        default="",
        help="file daftar akun email|password (khusus mode check_trial atau gmail_manual)",
    )
    ap.add_argument(
        "--account",
        default="",
        help="satu akun email|password langsung dari perintah",
    )
    args = ap.parse_args()

    _safe_print(f"{C_CYAN}{C_BOLD}{'=' * 60}{C_RESET}")
    _safe_print(f"{C_CYAN}{C_BOLD}   ZAYSE CAPCUT FARM - Account Farm & Cek Diskon Pipopay{C_RESET}")
    _safe_print(f"{C_CYAN}{C_BOLD}   Camoufox Anti-Detect Browser{C_RESET}")
    _safe_print(f"{C_CYAN}{C_BOLD}{'=' * 60}{C_RESET}")

    cfg_path = Path(args.config)
    if not cfg_path.is_file() and Path("config.example.json").is_file():
        shutil.copy("config.example.json", cfg_path)
        _safe_print(f"[!] created {cfg_path} from config.example.json — enter your Litensi credentials")

    cfg = load_config(cfg_path)
    if args.count is not None:
        cfg.register_count = max(1, args.count)
    if args.headless:
        cfg.headless = True
    if args.proxy:
        cfg.proxy = args.proxy
    if args.mail_provider:
        cfg.mail_provider = args.mail_provider
    if args.signup_mode:
        cfg.signup_mode = args.signup_mode

    try:
        # If gmail_manual mode is active
        if args.signup_mode == "gmail_manual" or args.mode == "check_trial":
            from capcut_farm.runner import run_trial_checker_job
            accounts = []
            raw_text = ""
            if args.account:
                raw_text = args.account
            elif args.accounts_file:
                acc_p = Path(args.accounts_file)
                if acc_p.is_file():
                    raw_text = acc_p.read_text(encoding="utf-8")
                else:
                    raw_text = args.accounts_file  # maybe user typed email|password directly in the argument

            if not raw_text.strip():
                _safe_print(f"\n{C_CYAN}{C_BOLD}[INPUT AKUN GMAIL / CAPCUT]{C_RESET}")
                _safe_print("Masukkan akun dengan format email|password (atau ketik nama file seperti accounts.txt):")
                user_inp = input(">> ").strip()
                acc_p = Path(user_inp)
                if acc_p.is_file():
                    raw_text = acc_p.read_text(encoding="utf-8")
                else:
                    raw_text = user_inp

            for line in raw_text.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = re.split(r"\||----|:::|::|:|\t", line, maxsplit=1)
                if len(parts) >= 2 and parts[1].strip():
                    accounts.append((parts[0].strip(), parts[1].strip()))
                elif " " in line and "@" in line:
                    sp = line.split(maxsplit=1)
                    if len(sp) >= 2:
                        accounts.append((sp[0].strip(), sp[1].strip()))
                    else:
                        accounts.append((line.strip(), ""))
                elif "@" in line:
                    accounts.append((line.strip(), ""))

            if not accounts:
                _safe_print(f"{C_RED}[ERROR] Format akun tidak valid! Masukkan: email|password{C_RESET}")
                input("Tekan Enter untuk kembali...")
                return 1

            _safe_print(f"{C_CYAN}[*] Memproses {len(accounts)} akun Gmail / CapCut (cek diskon & link Pipopay)...{C_RESET}")
            is_gmail_mode = (args.signup_mode == "gmail_manual")
            ok, fail, out, _ = run_trial_checker_job(accounts, cfg, log=cli_logger, use_google=is_gmail_mode)
        elif args.mode == "regist":
            ok, fail, out = run_job(cfg, log=cli_logger, check_trial=False, only_7days=False)
        else: # regist_trial (cek diskon / trial & link Pipopay)
            ok, fail, out = run_job(cfg, log=cli_logger, check_trial=True, only_7days=False)
    except KeyboardInterrupt:
        _safe_print(f"\n{C_YELLOW}{C_BOLD}[!] Dihentikan oleh pengguna (Ctrl+C){C_RESET}")
        return 130

    _safe_print("")
    _safe_print(f"{C_BLUE}{C_BOLD}{'=' * 60}{C_RESET}")
    _safe_print(f"{C_GREEN}{C_BOLD}🎉 PROSES SELESAI!{C_RESET}")
    _safe_print(f"   {C_GREEN}✅ Berhasil : {ok} akun{C_RESET}")
    _safe_print(f"   {C_RED if fail > 0 else C_RESET}❌ Gagal    : {fail} akun{C_RESET}")
    _safe_print(f"   📁 File Akun: {out}")
    _safe_print(f"   📝 File Log : farm.log")
    _safe_print(f"{C_BLUE}{C_BOLD}{'=' * 60}{C_RESET}")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
