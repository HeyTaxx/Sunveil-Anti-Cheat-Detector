@echo off
title Sunveil SMP Anti-Cheat Server
color 0B

echo ================================================================
echo                    SUNVEIL SMP
echo              Anti-Cheat API Dashboard
echo ================================================================
echo.
echo Starting Web Server...
echo.

cd /d "%~dp0api"
call npm install
cls

echo ================================================================
echo                    SUNVEIL SMP
echo              Anti-Cheat API Dashboard
echo ================================================================
echo.
echo Starting Server...
node server.js

pause
