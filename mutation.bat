@echo off
REM Remove every authorization check one at a time and prove a test fails for each.
cd /d "%~dp0"
call .venv\Scripts\activate.bat || (echo Run setup.bat first & exit /b 1)
python tools\mutation_check.py %*
