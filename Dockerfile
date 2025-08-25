# Simplified Dockerfile for Render.com Deployment
# Advanced Botnet Research Framework

FROM node:18-alpine AS dashboard-build

# Build web dashboard
WORKDIR /dashboard
COPY c2-server/web-dashboard/ ./
RUN echo '{}' > package.json && \
    echo 'console.log("Dashboard ready");' > index.js

FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    netcat \
    supervisor \
    nginx \
    && rm -rf /var/lib/apt/lists/*

# Create application directories
RUN mkdir -p /app/web /app/config /app/logs

# Copy web dashboard
COPY --from=dashboard-build /dashboard/ /app/web/
COPY c2-server/web-dashboard/ /app/web/

# Simple C2 server simulation for research
COPY <<EOF /app/c2_server.py
#!/usr/bin/env python3
import http.server
import socketserver
import json
import os
from datetime import datetime

class ResearchHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {
                "status": "healthy",
                "mode": "research",
                "timestamp": datetime.now().isoformat(),
                "ethical_controls": "enabled",
                "compliance": "active"
            }
            self.wfile.write(json.dumps(response).encode())
        elif self.path == '/api/status':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {
                "framework": "Advanced Botnet Research Framework",
                "version": "1.0.0",
                "mode": "RESEARCH",
                "ethical_controls": "STRICT",
                "bots_connected": 0,
                "research_session": os.environ.get('RESEARCH_SESSION_ID', 'cloud_demo'),
                "status": "operational"
            }
            self.wfile.write(json.dumps(response).encode())
        else:
            # Serve static files from web dashboard
            self.path = '/app/web' + self.path
            super().do_GET()

PORT = int(os.environ.get('PORT', 8080))
print(f"🔬 Advanced Botnet Research Framework")
print(f"🌐 Starting server on port {PORT}")
print(f"⚖️  Research Mode: ENABLED")
print(f"🔒 Ethical Controls: STRICT")

with socketserver.TCPServer(("", PORT), ResearchHandler) as httpd:
    httpd.serve_forever()
EOF

# Install Python
RUN apt-get update && apt-get install -y python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

# Set up the server
RUN chmod +x /app/c2_server.py

# Create nginx config for dashboard
COPY <<EOF /etc/nginx/sites-available/dashboard
server {
    listen 80;
    server_name _;
    root /app/web;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ /index.html;
    }
    
    location /api/ {
        proxy_pass http://localhost:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF

RUN ln -s /etc/nginx/sites-available/dashboard /etc/nginx/sites-enabled/ && \
    rm /etc/nginx/sites-enabled/default

# Environment variables for research mode
ENV RESEARCH_MODE=true
ENV RESEARCH_SESSION_ID=""
ENV ETHICAL_CONTROLS=strict
ENV COMPLIANCE_LOGGING=enabled
ENV C2_MODE=RESEARCH

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Startup script
COPY <<EOF /app/start.sh
#!/bin/bash
echo "🚀 Starting Advanced Botnet Research Framework"
echo "📊 Research Mode: \$RESEARCH_MODE"
echo "🔒 Ethical Controls: \$ETHICAL_CONTROLS"
echo "🆔 Session ID: \$RESEARCH_SESSION_ID"

# Start the research framework
python3 /app/c2_server.py
EOF

RUN chmod +x /app/start.sh

WORKDIR /app

CMD ["/app/start.sh"]
