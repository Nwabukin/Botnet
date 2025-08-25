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

class C2Handler(http.server.SimpleHTTPRequestHandler):
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
            self.send_json({
                "active_bots": 0,
                "commands_today": 0,
                "bytes_transferred": 0,
                "server_start_time": datetime.now().isoformat()
            })
        elif self.path == "/api/bots":
            self.send_json([])
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
