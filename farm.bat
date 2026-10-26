@echo off
REM ============================================================
REM  ZAYSE CAPCUT FARM - Launcher CLI Farm & Promo Checker
REM  Klik 2x -> langsung farm akun CapCut / Cek Diskon Pipopay
REM ============================================================
cd /d "%~dp0"
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1
if exist "C:\Python314\python.exe" (
    set PY=C:\Python314\python.exe
) else (
    set PY=python
)

echo ============================================================
echo   ZAYSE CAPCUT FARM - Account Farm ^& Cek Diskon Pipopay
echo   Camoufox Anti-Detect Browser
echo ============================================================
echo.
echo Pilih Metode Pendaftaran / Login:
echo   [1] Email  - Langsung CapCut (TempMail Otomatis / Gratis)
echo   [2] TikTok - TikTok Bridge SSO (Otomatis)
echo   [3] Gmail  - Manual Akun (Format: email^|password)
echo.
set METHOD=1
set /p METHOD="Pilih metode [1-3] default [1]: "

if "%METHOD%"=="3" goto :mode_gmail
if "%METHOD%"=="2" goto :mode_tiktok
goto :mode_email

:mode_gmail
echo.
echo ============================================================
echo   METODE GMAIL / CEK TRIAL AKUN MANUAL
echo   Log : farm.log (biarkan jendela ini terbuka)
echo ============================================================
echo.
"%PY%" main.py --signup-mode gmail_manual
goto :selesai

:mode_tiktok
set SIGNUP_MODE=tiktok
set MAIL_PROV=tempmail
set METHOD_NAME=TikTok Bridge SSO (Daftar TikTok -^> CapCut)
goto :ask_count

:mode_email
set SIGNUP_MODE=email
set MAIL_PROV=tempmail
set METHOD_NAME=Registrasi Email Langsung CapCut (TempMail)
goto :ask_count

:ask_count
echo.
set COUNT=1
set /p COUNT="Berapa akun yang ingin dibuat? [1]: "
if "%COUNT%"=="" set COUNT=1

echo.
echo ============================================================
echo  Metode : %METHOD_NAME%
echo  Target : %COUNT% akun
echo  Cek    : Diskon Promo ^& Link Pipopay (pipopay.com)
echo  Log    : farm.log (biarkan jendela ini terbuka)
echo ============================================================
echo.

"%PY%" main.py --count %COUNT% --signup-mode %SIGNUP_MODE% --mail-provider %MAIL_PROV%

:selesai
set RC=%ERRORLEVEL%
echo.
echo ============================================================
if "%RC%"=="0" (
    echo  SELESAI - lihat hasil akun di folder accounts\
) else (
    echo  SELESAI (ada catatan/gagal) - cek farm.log
)
echo ============================================================
pause
