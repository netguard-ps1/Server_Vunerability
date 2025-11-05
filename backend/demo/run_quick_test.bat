@echo off
echo ============================================================
echo Quick Test - 20 Packets (15 Malicious, 5 Benign)
echo ============================================================
echo.
echo Make sure packet capture is running!
echo Press any key to start...
pause > nul

python quick_test.py

pause
