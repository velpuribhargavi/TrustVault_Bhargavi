@echo off
REM Wipe the database, files, keys and audit trail, then re-create the demo data.
cd /d "%~dp0"
call .venv\Scripts\activate.bat || (echo Run setup.bat first & exit /b 1)
python scripts\init_db.py --reset --seed
