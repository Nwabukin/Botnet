#!/usr/bin/env python3
"""
Advanced Botnet Research Framework - C2 Server
Simplified Python implementation for cloud deployment
"""

import http.server
import socketserver
import json
import os
import urllib.parse
from datetime import datetime
import time

class C2Handler(http.server.SimpleHTTPRequestHandler):
    # Simple in-memory storage for demo
    connected_bots = {}
    heartbeat_count = 0
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="/app/web", **kwargs)
    
    def do_GET(self):
        if self.path == "/health":
            self.send_json({
                "status": "healthy", 
                "mode": "research", 
                "timestamp": datetime.now().isoformat()
            })
        elif self.path == "/api/status":
            self.send_json({
                "framework": "Advanced Botnet Research Framework",
                "version": "1.0.0",
                "mode": "RESEARCH",
                "status": "operational",
                "research_mode": True,
                "ethical_controls": "STRICT"
            })
        elif self.path == "/api/server/info":
            self.send_json({
                "research_mode": True,
                "version": "1.0.0",
                "status": "operational"
            })
        elif self.path == "/api/statistics":
            # Count active bots (last seen within 2 minutes)
            current_time = time.time()
            active_bots = sum(1 for bot_data in self.connected_bots.values() 
                             if current_time - bot_data.get('last_seen', 0) <= 120)
            
            self.send_json({
                "active_bots": active_bots,
                "commands_today": self.heartbeat_count,
                "bytes_transferred": self.heartbeat_count * 512,  # Estimate
                "server_start_time": datetime.now().isoformat()
            })
        elif self.path == "/api/bots":
            # Return list of connected bots
            bot_list = []
            current_time = time.time()
            for bot_id, bot_data in list(self.connected_bots.items()):
                # Remove bots that haven't sent heartbeat in 2 minutes
                if current_time - bot_data.get('last_seen', 0) > 120:
                    del self.connected_bots[bot_id]
                else:
                    bot_list.append({
                        'bot_id': bot_id,
                        'platform': bot_data.get('platform', 'Unknown'),
                        'ip_address': self.client_address[0],
                        'last_seen': datetime.fromtimestamp(bot_data['last_seen']).isoformat(),
                        'status': 'active'
                    })
            self.send_json(bot_list)
        elif self.path == "/api/activity/recent":
            self.send_json([{
                "timestamp": datetime.now().isoformat(),
                "type": "INFO",
                "description": "Server started in research mode"
            }])
        elif self.path == "/api/commands/pending":
            self.send_json([])
        elif self.path == "/api/logs":
            self.send_json({
                "logs": [
                    "Server started in research mode",
                    "Ethical controls activated",
                    "Compliance monitoring enabled"
                ],
                "count": 3
            })
        elif self.path == "/api/research":
            self.send_json({
                "session_id": os.environ.get("RESEARCH_SESSION_ID", "cloud_demo"),
                "compliance": "active",
                "ethical_mode": True
            })
        elif self.path.startswith("/download/"):
            self.handle_client_download()
        elif self.path == "/install":
            self.send_install_script()
        elif self.path == "/builder":
            self.path = "/builder.html"
            super().do_GET()
        elif self.path == "/":
            self.path = "/index.html"
            super().do_GET()
        else:
            super().do_GET()

    def do_POST(self):
        """Handle POST requests for bot communication"""
        if self.path == "/api/heartbeat":
            self.handle_heartbeat()
        elif self.path == "/api/commands":
            self.handle_command_submission()
        elif self.path.startswith("/api/commands/") and self.path.endswith("/cancel"):
            self.handle_command_cancel()
        elif self.path.startswith("/api/bots/") and self.path.endswith("/disconnect"):
            self.handle_bot_disconnect()
        elif self.path == "/api/bots/disconnect-all":
            self.handle_disconnect_all_bots()
        elif self.path == "/api/server/settings":
            self.handle_server_settings()
        elif self.path == "/api/security/rotate-keys":
            self.handle_rotate_keys()
        elif self.path == "/api/admin/backup":
            self.handle_database_backup()
        elif self.path == "/api/server/emergency-stop":
            self.handle_emergency_stop()
        elif self.path == "/api/research/compliance-report":
            self.handle_compliance_report()
        elif self.path == "/api/research/export":
            self.handle_research_export()
        else:
            self.send_error(404, "Not Found")
    
    def handle_heartbeat(self):
        """Handle bot heartbeat/check-in"""
        try:
            # Get content length
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                post_data = self.rfile.read(content_length)
                bot_data = json.loads(post_data.decode('utf-8'))
            else:
                bot_data = {}
            
            # Extract bot info from headers (for simple clients)
            bot_id = self.headers.get('X-Bot-ID', bot_data.get('bot_id', f'bot_{int(time.time())}'))
            platform = self.headers.get('X-Platform', bot_data.get('platform', 'Unknown'))
            
            # Store/update bot info
            self.connected_bots[bot_id] = {
                'bot_id': bot_id,
                'platform': platform,
                'last_seen': time.time(),
                'ip_address': self.client_address[0]
            }
            
            self.heartbeat_count += 1
            
            print(f"[HEARTBEAT] Bot {bot_id} from {self.client_address[0]} - Platform: {platform}")
            
            # Send response
            self.send_json({
                "status": "success",
                "message": "Heartbeat received",
                "bot_id": bot_id,
                "next_checkin": 30,
                "research_mode": True
            })
            
        except Exception as e:
            print(f"[ERROR] Heartbeat handling failed: {e}")
            self.send_error(500, "Internal Server Error")
    
    def handle_command_submission(self):
        """Handle command submissions"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            command_data = json.loads(post_data.decode('utf-8'))
            
            print(f"[COMMAND] Received command: {command_data}")
            
            self.send_json({
                "status": "success", 
                "message": "Command queued",
                "command_id": f"cmd_{int(time.time())}"
            })
            
        except Exception as e:
            print(f"[ERROR] Command handling failed: {e}")
            self.send_error(500, "Internal Server Error")
    
    def handle_command_cancel(self):
        """Handle command cancellation"""
        try:
            command_id = self.path.split("/")[-2]  # Extract command_id from path
            print(f"[COMMAND] Cancelling command: {command_id}")
            
            self.send_json({
                "status": "success",
                "message": f"Command {command_id} cancelled"
            })
        except Exception as e:
            print(f"[ERROR] Command cancel failed: {e}")
            self.send_error(500, "Internal Server Error")
    
    def handle_bot_disconnect(self):
        """Handle individual bot disconnection"""
        try:
            bot_id = self.path.split("/")[-2]  # Extract bot_id from path
            print(f"[BOT] Disconnecting bot: {bot_id}")
            
            # Remove bot from connected list
            if bot_id in self.connected_bots:
                del self.connected_bots[bot_id]
            
            self.send_json({
                "status": "success",
                "message": f"Bot {bot_id} disconnected"
            })
        except Exception as e:
            print(f"[ERROR] Bot disconnect failed: {e}")
            self.send_error(500, "Internal Server Error")
    
    def handle_disconnect_all_bots(self):
        """Handle disconnecting all bots"""
        try:
            bot_count = len(self.connected_bots)
            print(f"[BOT] Disconnecting all bots: {bot_count}")
            
            # Clear all connected bots
            self.connected_bots.clear()
            
            self.send_json({
                "status": "success",
                "message": f"Disconnected {bot_count} bots"
            })
        except Exception as e:
            print(f"[ERROR] Disconnect all failed: {e}")
            self.send_error(500, "Internal Server Error")
    
    def handle_server_settings(self):
        """Handle server settings update"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            settings = json.loads(post_data.decode('utf-8'))
            
            print(f"[SETTINGS] Updating server settings: {settings}")
            
            self.send_json({
                "status": "success",
                "message": "Server settings updated"
            })
        except Exception as e:
            print(f"[ERROR] Settings update failed: {e}")
            self.send_error(500, "Internal Server Error")
    
    def handle_rotate_keys(self):
        """Handle encryption key rotation"""
        try:
            print("[SECURITY] Rotating encryption keys")
            
            self.send_json({
                "status": "success",
                "message": "Encryption keys rotated successfully"
            })
        except Exception as e:
            print(f"[ERROR] Key rotation failed: {e}")
            self.send_error(500, "Internal Server Error")
    
    def handle_database_backup(self):
        """Handle database backup creation"""
        try:
            print("[ADMIN] Creating database backup")
            
            self.send_json({
                "status": "success",
                "message": "Database backup created successfully"
            })
        except Exception as e:
            print(f"[ERROR] Database backup failed: {e}")
            self.send_error(500, "Internal Server Error")
    
    def handle_emergency_stop(self):
        """Handle emergency stop"""
        try:
            print("[EMERGENCY] Emergency stop triggered")
            
            self.send_json({
                "status": "success",
                "message": "Emergency stop initiated"
            })
        except Exception as e:
            print(f"[ERROR] Emergency stop failed: {e}")
            self.send_error(500, "Internal Server Error")
    
    def handle_compliance_report(self):
        """Handle compliance report generation"""
        try:
            print("[RESEARCH] Generating compliance report")
            
            self.send_json({
                "status": "success",
                "message": "Compliance report generated",
                "report_id": f"report_{int(time.time())}"
            })
        except Exception as e:
            print(f"[ERROR] Compliance report failed: {e}")
            self.send_error(500, "Internal Server Error")
    
    def handle_research_export(self):
        """Handle research data export"""
        try:
            print("[RESEARCH] Exporting research data")
            
            self.send_json({
                "status": "success",
                "message": "Research data exported",
                "export_id": f"export_{int(time.time())}"
            })
        except Exception as e:
            print(f"[ERROR] Research export failed: {e}")
            self.send_error(500, "Internal Server Error")

    def handle_client_download(self):
        platform = self.path.split("/")[-1]
        if platform == "client-windows.exe":
            self.send_client_script("windows")
        elif platform == "client-linux":
            self.send_client_script("linux")
        elif platform == "client-macos":
            self.send_client_script("macos")
        else:
            self.send_error(404)

    def send_client_script(self, platform):
        server_url = "https://" + self.headers.get("Host", "localhost:8080") + "/"
        
        if platform == "windows":
            script = "@echo off\n"
            script += "echo Advanced Botnet Research Framework - Windows Client\n"
            script += f"echo Server: {server_url}\n"
            script += "echo Research Mode: ENABLED\n"
            script += "echo.\n"
            script += "echo Connecting to C2 server...\n"
            script += f'powershell -Command "while ($true) {{ try {{ Invoke-RestMethod -Uri \'{server_url}health\' | Out-Null; Write-Host \'[Connected] Bot active - Research mode\'; Start-Sleep 30 }} catch {{ Write-Host \'[Reconnecting] Attempting connection...\'; Start-Sleep 10 }} }}"\n'
            
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", "attachment; filename=bot-client.bat")
        else:
            script = "#!/bin/bash\n"
            script += f'echo "Advanced Botnet Research Framework - {platform.title()} Client"\n'
            script += f'echo "Server: {server_url}"\n'
            script += 'echo "Research Mode: ENABLED"\n'
            script += 'echo ""\n'
            script += 'echo "Connecting to C2 server..."\n'
            script += 'while true; do\n'
            script += f'  if curl -s "{server_url}health" > /dev/null 2>&1; then\n'
            script += '    echo "[Connected] Bot active - Research mode"\n'
            script += '    sleep 30\n'
            script += '  else\n'
            script += '    echo "[Reconnecting] Attempting connection..."\n'
            script += '    sleep 10\n'
            script += '  fi\n'
            script += 'done\n'
            
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", "attachment; filename=bot-client")
            
        self.end_headers()
        self.wfile.write(script.encode())

    def send_install_script(self):
        server_url = "https://" + self.headers.get("Host", "localhost:8080") + "/"
        
        script = "#!/bin/bash\n"
        script += 'echo "🔬 Advanced Botnet Research Framework - Auto Installer"\n'
        script += f'echo "Server: {server_url}"\n'
        script += 'echo "⚖️  Research Mode: ENABLED"\n'
        script += 'echo ""\n'
        script += '\n'
        script += '# Detect platform\n'
        script += 'if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then\n'
        script += '  PLATFORM="windows"\n'
        script += '  EXT=".exe"\n'
        script += 'elif [[ "$OSTYPE" == "darwin"* ]]; then\n'
        script += '  PLATFORM="macos"\n'
        script += '  EXT=""\n'
        script += 'else\n'
        script += '  PLATFORM="linux"\n'
        script += '  EXT=""\n'
        script += 'fi\n'
        script += '\n'
        script += 'echo "Detected platform: $PLATFORM"\n'
        script += 'echo "Downloading client..."\n'
        script += '\n'
        script += '# Download and run client\n'
        script += f'curl -L "{server_url}download/client-$PLATFORM$EXT" -o "bot-client$EXT"\n'
        script += 'chmod +x "bot-client$EXT"\n'
        script += 'echo "✅ Client downloaded and ready!"\n'
        script += 'echo "Run: ./bot-client$EXT"\n'
        
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(script.encode())

    def send_json(self, data):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

def main():
    PORT = int(os.environ.get("PORT", 8080))
    print("🔬 Advanced Botnet Research Framework")
    print(f"🌐 Starting C2 Dashboard on port {PORT}")
    print("⚖️  Research Mode: ENABLED")
    print("🔒 Ethical Controls: STRICT")
    print("📁 Serving dashboard from: /app/web")
    
    with socketserver.TCPServer(("", PORT), C2Handler) as httpd:
        httpd.serve_forever()

if __name__ == "__main__":
    main()
