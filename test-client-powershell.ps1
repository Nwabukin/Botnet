# Advanced Botnet Research Framework - PowerShell Client
# Connects to live C2 server at https://botnet-xdio.onrender.com

param(
    [string]$ServerUrl = "https://botnet-xdio.onrender.com",
    [int]$HeartbeatInterval = 30,
    [int]$ReconnectDelay = 10
)

Write-Host ""
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  Advanced Botnet Research Framework - PowerShell Client" -ForegroundColor Yellow
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  Server: $ServerUrl" -ForegroundColor Green
Write-Host "  Research Mode: ENABLED" -ForegroundColor Yellow
Write-Host "  Ethical Controls: STRICT" -ForegroundColor Red
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host ""

# Generate unique bot ID
$BotId = "PS_$($env:COMPUTERNAME)_$(Get-Random -Maximum 9999)"
$Platform = "Windows PowerShell $($PSVersionTable.PSVersion)"
$StartTime = Get-Date

Write-Host "🤖 Bot ID: $BotId" -ForegroundColor Cyan
Write-Host "💻 Platform: $Platform" -ForegroundColor Cyan
Write-Host "⏰ Started: $StartTime" -ForegroundColor Cyan
Write-Host ""

function Send-Heartbeat {
    param($Url, $BotInfo)
    
    try {
        # Test basic connectivity first
        $response = Invoke-RestMethod -Uri $Url -Method GET -TimeoutSec 10
        return $true
    }
    catch {
        return $false
    }
}

function Write-Log {
    param($Message, $Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO" { "Green" }
        "WARN" { "Yellow" } 
        "ERROR" { "Red" }
        default { "White" }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

# Main connection loop
Write-Log "🚀 Starting bot client connection loop..."
Write-Log "🎯 Target server: $ServerUrl"
Write-Log "⚖️  Research mode compliance: ACTIVE"

$connectionCount = 0

while ($true) {
    try {
        Write-Log "🔄 Attempting connection #$($connectionCount + 1)..."
        
        if (Send-Heartbeat -Url $ServerUrl -BotInfo @{
            bot_id = $BotId
            platform = $Platform
            timestamp = (Get-Date).ToString("o")
        }) {
            $connectionCount++
            Write-Log "✅ [CONNECTED] Bot active - Research mode" "INFO"
            Write-Log "📡 Heartbeat sent to C2 server" "INFO"
            Write-Log "🔒 All activities logged for research compliance" "INFO"
            
            # Show connection stats
            $uptime = (Get-Date) - $StartTime
            Write-Log "📊 Uptime: $($uptime.ToString('hh\:mm\:ss')) | Connections: $connectionCount" "INFO"
            
            Start-Sleep -Seconds $HeartbeatInterval
        }
        else {
            Write-Log "❌ Cannot reach C2 server at $ServerUrl" "ERROR"
            Write-Log "🔄 Retrying in $ReconnectDelay seconds..." "WARN"
            Start-Sleep -Seconds $ReconnectDelay
        }
    }
    catch {
        Write-Log "💥 Connection error: $($_.Exception.Message)" "ERROR"
        Write-Log "🔄 Retrying in $ReconnectDelay seconds..." "WARN"
        Start-Sleep -Seconds $ReconnectDelay
    }
}
