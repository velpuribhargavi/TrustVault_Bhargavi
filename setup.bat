@echo off
REM One-time setup on Windows: virtual environment, dependencies, database, demo data.
setlocal
cd /d "%~dp0"
set PY=python
where python >nul 2>nul || set PY=py -3
%PY% --version >nul 2>nul || (echo Python 3.10 or newer is required: https://www.python.org/downloads/ & exit /b 1)
if not exist .venv (
  echo Creating virtual environment...
  %PY% -m venv .venv || exit /b 1
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt || exit /b 1
python scripts\init_db.py --seed || exit /b 1
echo.
echo Setup complete.  Start the server with:  run.bat
echo Run the tests with:                      test.bat
