@echo off
REM Uploads every change in this folder to GitHub every 5 minutes while this window is open.
REM instance\ (keys, database) is never uploaded: it is listed in .gitignore.
cd /d "%~dp0"
title TrustVault auto-sync
echo Auto-sync running for %CD%
echo Close this window or press Ctrl+C to stop.
:loop
git add -A
git diff --cached --quiet || git commit -q -m "Auto-save %date% %time:~0,5%"
git push -q origin main && echo [%time:~0,5%] synced with GitHub || echo [%time:~0,5%] push failed - will retry in 5 minutes
timeout /t 300 /nobreak >nul
goto loop
