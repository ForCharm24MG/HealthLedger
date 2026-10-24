@echo off
title HealthLedger Desktop Workstation - Research Prototype
cd /d "%~dp0"
echo Starting Enterprise PyQt5 Hospital Desktop Workstation...
python gui_app.py
if errorlevel 1 pause
