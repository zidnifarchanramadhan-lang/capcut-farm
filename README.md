# ZAYSE CAPCUT FARM

Automated CapCut account registration, TikTok bridge SSO, and Pipopay promo / trial checker using Camoufox Anti-Detect browser.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Engine](https://img.shields.io/badge/Engine-Camoufox-orange.svg)](https://github.com/daij-djan/camoufox)
[![Automation](https://img.shields.io/badge/Automation-Playwright-green.svg)](https://playwright.dev/)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

---

## Deskripsi

Zayse CapCut Farm adalah perangkat otomatisasi untuk registrasi akun CapCut secara massal, login melalui TikTok Bridge SSO, serta pemeriksaan promo diskon dan Free Trial Pipopay (termasuk link checkout cashier).

Otomatisasi menggunakan engine browser **Camoufox** (berbasis Firefox stealth) dengan randomisasi fingerprint, emulasi mouse, dan penanganan anti-bot seperti Cloudflare dan DataDome.

![Tampilan Antarmuka CLI](assets/preview.png)

---

## Fitur

- **Anti-Detect Camoufox**: Bypass deteksi otomasi tanpa browser consumer biasa.
- **Dua Metode Registrasi**:
  - `tiktok`: Mendaftar akun TikTok secara otomatis, lalu login ke CapCut via TikTok SSO (*Continue with TikTok*).
  - `email`: Mendaftar langsung melalui formulir email CapCut (tanggal lahir, password, verifikasi kode OTP).
- **Pipopay Promo & Trial Checker**:
  - Deteksi ketersediaan kupon diskon dan penawaran Free Trial (Rp0).
  - Ekstraksi langsung link pembayaran `https://cashier.pipopay.com/pay/...`.
- **Dukungan Provider Email**:
  - `tempmail` / `yourmail`: REST API TempMail otomatis.
  - `gmail_dot`: Alias Gmail dot-trick dengan pembacaan OTP via IMAP (Google App Password).
  - `mailcx` dan `litensi`: Provider pihak ketiga.
- **Proxy Management**:
  - Mendukung protokol HTTP, HTTPS, dan SOCKS5 dengan autentikasi.
  - Rotasi proxy lokal bawaan melalui `proxy_rotator.py`.
- **Eksekusi Windows & CLI**:
  - Tersedia launcher batch (`install.bat`, `farm.bat`) untuk Windows.
  - CLI argument fleksibel untuk Linux/server/headless.

---

## Struktur Proyek

```text
zayse-capcut-farm/
|-- accounts/                  # Hasil output akun yang tersimpan
|-- assets/                    # Asset gambar dan screenshot preview
|-- capcut_farm/               # Modul logika pendaftaran dan automation
|   |-- config.py              # Parser konfigurasi
|   |-- gmail_dot.py           # Provider Gmail via IMAP
|   |-- litensi.py             # Provider Litensi Mail API
|   |-- mailcx.py              # Provider Mail.cx API
|   |-- yourmail.py            # Provider TempMail / YourMail API
|   |-- profiles.py            # Profil browser dan manajemen fingerprint
|   `-- runner.py              # Alur otomasi CapCut, SSO, dan promo checker
|-- .env.example               # Contoh variabel environment
|-- .gitignore                 # Konfigurasi filter Git
|-- config.example.json        # Template konfigurasi default
|-- config.json                # Konfigurasi aktif (lokal)
|-- farm.bat                   # Launcher pendaftaran Windows
|-- install.bat                # Script instalasi Windows
|-- main.py                    # Entry point program
|-- proxies.txt                # Daftar proxy (opsional)
|-- proxy_rotator.py           # Local rotating proxy server
|-- requirements.txt           # Dependensi pustaka Python
`-- README.md                  # Dokumentasi proyek
```

---

## Persyaratan Sistem

- Python 3.10 atau versi di atasnya (disarankan 3.11, 3.12, atau 3.14).
- Opsi **Add python.exe to PATH** wajib aktif saat instalasi Python di Windows.
- Koneksi internet stabil untuk download binary browser Camoufox.

---

## Instalasi

### Windows (Script Otomatis)

1. Clone repositori:
   ```bash
   git clone https://github.com/zidnifarchanramadhan-lang/capcut-farm.git
   cd capcut-farm
   ```
2. Jalankan `install.bat` (klik dua kali) untuk memasang seluruh dependensi dan mengunduh binary Camoufox.
3. Jalankan `farm.bat` (klik dua kali) untuk memulai.

### Manual / Linux / Terminal

1. Setup virtual environment (opsional):
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Di Windows: .venv\Scripts\activate
   ```
2. Pasang dependensi:
   ```bash
   pip install -r requirements.txt
   ```
3. Unduh binary browser Camoufox:
   ```bash
   python -m camoufox fetch
   ```
4. Siapkan file konfigurasi:
   ```bash
   cp config.example.json config.json
   ```

---

## Konfigurasi (`config.json`)

Contoh isi `config.json`:

```json
{
  "mail_provider": "tempmail",
  "signup_mode": "tiktok",
  "yourmail_api_url": "https://your-api-temp-mail.com/api",
  "yourmail_domain": "",
  "yourmail_custom_prefix": "",
  "gmail_address": "",
  "gmail_app_password": "",
  "register_count": 1,
  "proxy": "",
  "proxy_file": "proxies.txt",
  "headless": false,
  "delay_sec": 5.0,
  "max_username_tries": 6,
  "otp_timeout_sec": 240,
  "fresh_profile": true
}
```

### Penjelasan Parameter

| Field | Tipe | Keterangan |
|---|---|---|
| `mail_provider` | string | Pilihan: `"tempmail"`, `"yourmail"`, `"gmail_dot"`, `"mailcx"`, `"litensi"`. |
| `signup_mode` | string | Pilihan: `"tiktok"` (SSO TikTok), `"email"` (Direct CapCut), `"gmail_manual"`. |
| `yourmail_api_url` | string | URL endpoint REST API TempMail / YourMail. |
| `yourmail_domain` | string | Domain kustom TempMail (kosongkan jika otomatis). |
| `gmail_address` | string | Alamat email Gmail jika menggunakan provider `gmail_dot`. |
| `gmail_app_password` | string | 16-digit App Password Gmail (bukan password akun biasa). |
| `register_count` | integer | Jumlah akun yang diproses. |
| `proxy` | string | Single proxy URL (`http://user:pass@host:port`). |
| `proxy_file` | string | File daftar proxy pool (default: `proxies.txt`). |
| `headless` | boolean | `true` untuk mode tanpa jendela browser, `false` untuk menampilkan browser. |
| `delay_sec` | float | Jeda waktu antar aksi dalam detik. |
| `otp_timeout_sec` | integer | Batas waktu tunggu OTP dalam detik. |
| `fresh_profile` | boolean | `true` untuk mereset profil browser per akun. |

---

## Panduan Setup Email Provider

Bot memerlukan akses inbox email untuk membaca kode verifikasi OTP dari CapCut maupun TikTok. Pilih metode yang sesuai kebutuhan:

### 1. Metode Gmail Dot-Trick (gmail_dot) - Rekomendasi Tanpa Server API

Metode ini menggunakan satu akun Gmail pribadi untuk menghasilkan variasi alias tanpa batas (contoh: `u.ser@gmail.com`, `us.er@gmail.com`). Bot membaca pesan masuk dan OTP langsung dari inbox Gmail melalui protokol IMAP.

Langkah konfigurasi:
1. Masuk ke Akun Google > Keamanan > aktifkan **Verifikasi 2 Langkah (2-Step Verification)**.
2. Buka halaman **Sandi Aplikasi (App Passwords)** di Google Account:
   `https://myaccount.google.com/apppasswords`
3. Buat sandi aplikasi baru dengan nama bebas (Google akan memberikan 16 karakter acak).
4. Masukkan ke dalam `config.json`:
   ```json
   "mail_provider": "gmail_dot",
   "gmail_address": "emailmu@gmail.com",
   "gmail_app_password": "xxxx xxxx xxxx xxxx"
   ```

### 2. Metode REST API TempMail (tempmail / yourmail)

Metode ini digunakan jika Anda memiliki server backend Temp Mail sendiri atau menggunakan layanan pihak ketiga yang kompatibel.

Langkah konfigurasi:
1. Atur URL endpoint API di `config.json`:
   ```json
   "mail_provider": "tempmail",
   "yourmail_api_url": "https://api-tempmail-kamu.com/api",
   "yourmail_domain": ""
   ```
2. Spesifikasi endpoint REST API yang diakses bot:
   - `GET /api/domains` : Mengembalikan daftar domain aktif (array string atau JSON `{ success: true, domains: [...] }`).
   - `POST /api/new-address?domain=&custom=` : Membuat alamat email baru dan mengembalikan token mailbox (`X-Mailbox-Token`).
   - `GET /api/messages?address=` : Mengambil daftar pesan masuk (disertai header `X-Mailbox-Token`).
   - `GET /api/message/:id?address=` : Mengambil detail isi email untuk parsing kode verifikasi OTP.
   - `DELETE /api/address?address=` : Menghapus mailbox setelah registrasi selesai.

### 3. Provider Alternatif (mailcx / litensi)

- **Mail.cx (`mailcx`)**: Menggunakan API publik Mail.cx. Cukup set `"mail_provider": "mailcx"` dan opsional nama domain di `"mailcx_domain"`.
- **Litensi (`litensi`)**: Untuk pengguna layanan Litensi. Isi `"litensi_api_id"` dan `"litensi_api_key"` di `config.json`.

---

## Penggunaan Proxy

Daftar proxy dapat diisi pada file `proxies.txt` (satu proxy per baris). Format yang didukung:

```text
http://user:pass@host:port
socks5://user:pass@host:port
host:port:user:pass
user:pass:host:port
```

Jika `proxies.txt` kosong atau semua baris berupa komentar (`#`), bot berjalan menggunakan koneksi internet langsung.

### Local Proxy Rotator (Opsional)

Untuk memutar proxy pool melalui port lokal tunggal:

```bash
python proxy_rotator.py --port 8099 --proxies proxies.txt
```

Set konfigurasi di `config.json`:
```json
"proxy": "http://127.0.0.1:8099"
```

---

## Penggunaan CLI

Perintah dapat dijalankan langsung via terminal:

```bash
# Registrasi akun via TikTok Bridge SSO
python main.py --count 5 --signup-mode tiktok --mail-provider tempmail

# Registrasi langsung form email CapCut
python main.py --count 3 --signup-mode email --mail-provider tempmail

# Menjalankan di background (headless)
python main.py --count 10 --signup-mode tiktok --headless

# Cek promo untuk akun tertentu (format: email|password)
python main.py --signup-mode gmail_manual --account "user@example.com|Password123"

# Cek promo massal dari file daftar akun
python main.py --signup-mode gmail_manual --accounts-file daftar_akun.txt
```

---

## Format Output

File output disimpan di direktori `accounts/`:

1. **Akun Lolos Promo / Trial (dengan link Pipopay)**:
   - File: `accounts/capcut_accounts_YYYYMMDD_HHMMSS.txt`
   - Format:
     ```text
     email----password----name----https://cashier.pipopay.com/pay/...
     ```

2. **Akun Tanpa Promo**:
   - File: `accounts/capcut_accounts_no_promo.txt`
   - Format:
     ```text
     email----password----name
     ```

Log eksekusi tercatat di file `farm.log`.

---

## Troubleshooting

- **Python tidak terdeteksi**: Pastikan `python` terdaftar di PATH environment variables. Cek dengan `python --version`.
- **Gagal mengunduh browser Camoufox**: Jalankan ulang `python -m camoufox fetch` dengan koneksi internet yang stabil.
- **Timeout OTP**: Periksa apakah domain email terkena limit/block atau coba alihkan ke provider lain (misal `gmail_dot`).
- **Captcha manual**: Jika captcha visual muncul, selesaikan interaksi captcha pada jendela browser (pastikan `headless: false`).

---

## Lisensi & Disclaimer

Proyek ini berlisensi [MIT](LICENSE).

Penggunaan perangkat lunak ini ditujukan untuk kebutuhan riset otomasi, pengujian sistem, dan edukasi. Pengguna bertanggung jawab penuh atas segala bentuk kepatuhan terhadap Terms of Service layanan terkait.
