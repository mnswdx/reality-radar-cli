@echo off
chcp 65001 > nul
title Reality Radar & Sentinel
python "%~dp0reality_radar.py" %*
pause
