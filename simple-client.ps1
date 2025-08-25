# Simple PowerShell Bot Client for Testing
# Connects to live C2 server

$ServerUrl = "https://botnet-xdio.onrender.com"
$BotId = "PS_$($env:COMPUTERNAME)_$(Get-Random -Maximum 9999)"

Write-Host ""
Write-Host "Advanced Botnet Research Framework - PowerShell Client" -ForegroundColor Yellow
Write-Host "Server: $ServerUrl" -ForegroundColor Green
Write-Host "Bot ID: $BotId" -ForegroundColor Cyan
Write-Host "Research Mode: ENABLED" -ForegroundColor Red
Write-Host ""

$connectionCount = 0
$startTime = Get-Date

while ($true) {
    $timestamp = Get-Date -Format "HH:mm:ss"
    
    try {
        # Test connection to server
        $response = Invoke-RestMethod -Uri $ServerUrl -Method GET -TimeoutSec 10
        
        $connectionCount++
        Write-Host "[$timestamp] [CONNECTED] Bot active - Research mode (Connection #$connectionCount)" -ForegroundColor Green
        
        $uptime = (Get-Date) - $startTime
        Write-Host "[$timestamp] Uptime: $($uptime.ToString('hh\:mm\:ss')) | Heartbeat sent" -ForegroundColor Cyan
        
        Start-Sleep -Seconds 30
    }
    catch {
        Write-Host "[$timestamp] [ERROR] Cannot reach C2 server - Retrying in 10 seconds..." -ForegroundColor Red
        Start-Sleep -Seconds 10
    }
}
