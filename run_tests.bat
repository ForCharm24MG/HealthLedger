@echo off
title HealthLedger - Automated Functional & Security Test Suite (16 Tests)
cd /d "%~dp0"
echo Running automated verification tests...
python test_suite.py
echo.
pause
