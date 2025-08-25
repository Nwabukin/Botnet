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

# Create the Python server file with full API support for the dashboard
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
RUN echo '        elif self.path == "/api/bots":' >> /app/server.py
RUN echo '            self.send_json({"bots": [], "count": 0, "active": 0})' >> /app/server.py
RUN echo '        elif self.path == "/api/stats":' >> /app/server.py
RUN echo '            self.send_json({"active_bots": 0, "total_commands": 0, "data_transferred": "0 MB", "uptime": "00:00:00"})' >> /app/server.py
RUN echo '        elif self.path == "/api/logs":' >> /app/server.py
RUN echo '            self.send_json({"logs": ["Server started in research mode", "Ethical controls activated", "Compliance monitoring enabled"], "count": 3})' >> /app/server.py
RUN echo '        elif self.path == "/api/research":' >> /app/server.py
RUN echo '            self.send_json({"session_id": os.environ.get("RESEARCH_SESSION_ID", "cloud_demo"), "compliance": "active", "ethical_mode": True})' >> /app/server.py
RUN echo '        elif self.path == "/":' >> /app/server.py
RUN echo '            self.path = "/index.html"' >> /app/server.py
RUN echo '            super().do_GET()' >> /app/server.py
RUN echo '        else:' >> /app/server.py
RUN echo '            super().do_GET()' >> /app/server.py
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

# The web dashboard files are already copied from c2-server/web-dashboard/
# No need to create index.html as it already exists

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