@echo off
echo ============================================================
echo Demo Packet Generator - Windows Launcher
echo ============================================================
echo.
echo This script will generate test packets for malware detection.
echo Make sure your packet capture is running in the Dashboard!
echo.
echo Press any key to start, or Ctrl+C to cancel...
pause > nul

echo.
echo Starting packet generation...
echo.

python generate_test_packets.py

echo.
echo Press any key to exit...
pause > nul
