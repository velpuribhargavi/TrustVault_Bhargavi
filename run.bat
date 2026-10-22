@echo off
REM Start TrustVault on http://127.0.0.1:8000  (extra arguments, e.g. --port 9000, are passed through)
cd /d "%~dp0"
call .venv\Scripts\activate.bat || (echo Run setup.bat first & exit /b 1)
python -m trustvault %*
