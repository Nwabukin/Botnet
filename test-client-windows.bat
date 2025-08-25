@echo off
echo.
echo ====================================================
echo   Advanced Botnet Research Framework - Windows Client
echo ====================================================
echo   Server: https://botnet-xdio.onrender.com
echo   Research Mode: ENABLED
echo   Ethical Controls: STRICT
echo ====================================================
echo.

:connect_loop
echo [%time%] Attempting to connect to C2 server...

REM Test server connectivity
curl -s "https://botnet-xdio.onrender.com/" >nul 2>&1
if %errorlevel% == 0 (
    echo [%time%] [CONNECTED] Bot active - Research mode
    echo [%time%] Sending heartbeat to server...
    
    REM Send bot registration (simulated)
    echo [%time%] Bot ID: WIN_%COMPUTERNAME%_%RANDOM%
    echo [%time%] Platform: Windows %OS%
    echo [%time%] Status: Online - Research Mode
    
    timeout /t 30 /nobreak >nul
) else (
    echo [%time%] [ERROR] Cannot reach C2 server
    echo [%time%] [RECONNECTING] Attempting connection in 10 seconds...
    timeout /t 10 /nobreak >nul
)

goto connect_loop