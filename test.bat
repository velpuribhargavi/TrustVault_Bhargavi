@echo off
REM Run the automated test suite (extra arguments are passed to pytest, e.g. test.bat -k share)
cd /d "%~dp0"
call .venv\Scripts\activate.bat || (echo Run setup.bat first & exit /b 1)
python -m pytest %*
