@echo off
cd /d "%~dp0"
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

if exist "C:\Python314\python.exe" (
    set PY=C:\Python314\python.exe
) else (
    set PY=python
)

echo ============================================
echo   ZAYSE CAPCUT FARM - Installer Dependencies
echo ============================================
echo.
echo Menggunakan Python: %PY%
%PY% --version
if errorlevel 1 (
    echo [ERROR] Python tidak terdeteksi!
    echo Pastikan Python sudah diinstall dan opsi 'Add python.exe to PATH' dicentang saat install.
    pause
    exit /b 1
)
echo.
echo [1/2] Menginstall dependencies requirements.txt...
"%PY%" -m pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Gagal install requirements!
    pause
    exit /b 1
)

echo.
echo [2/2] Mengunduh browser Camoufox...
"%PY%" -m camoufox fetch
if errorlevel 1 (
    echo [ERROR] Gagal fetch camoufox!
    pause
    exit /b 1
)

echo.
echo ============================================
echo   INSTALASI BERHASIL!
echo ============================================
echo Langkah berikutnya:
echo 1. Edit 'config.json' jika diperlukan (API url / proxy)
echo 2. Edit 'proxies.txt' jika ingin menggunakan proxy
echo 3. Jalankan 'farm.bat' untuk mulai farm akun CapCut
echo ============================================
pause
