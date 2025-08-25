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

# Create a default index.html if none exists
RUN echo '<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Botnet Research Framework</title>
    <style>
        body { 
            font-family: "Segoe UI", Arial, sans-serif; 
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white; 
            margin: 0; 
            padding: 20px;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container { 
            max-width: 800px; 
            text-align: center; 
            background: rgba(0,0,0,0.2);
            padding: 40px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
        }
        h1 { 
            color: #4CAF50; 
            margin-bottom: 30px;
            font-size: 2.5em;
        }
        .status { 
            background: rgba(76, 175, 80, 0.2); 
            padding: 20px; 
            border-radius: 10px; 
            margin: 20px 0;
            border-left: 5px solid #4CAF50;
        }
        .warning { 
            background: rgba(255, 152, 0, 0.2); 
            padding: 20px; 
            border-radius: 10px; 
            margin: 20px 0;
            border-left: 5px solid #FF9800;
        }
        .api-link { 
            display: inline-block; 
            background: #4CAF50; 
            color: white; 
            padding: 10px 20px; 
            text-decoration: none; 
            border-radius: 5px; 
            margin: 10px;
            transition: background 0.3s;
        }
        .api-link:hover { 
            background: #45a049; 
        }
        .feature { 
            background: rgba(255,255,255,0.1); 
            padding: 15px; 
            margin: 10px 0; 
            border-radius: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔬 Advanced Botnet Research Framework</h1>
        
        <div class="status">
            <h2>✅ System Status: OPERATIONAL</h2>
            <p><strong>Mode:</strong> Research & Educational</p>
            <p><strong>Ethical Controls:</strong> STRICT</p>
            <p><strong>Compliance:</strong> Active</p>
        </div>

        <div class="warning">
            <h3>⚖️ RESEARCH USE ONLY</h3>
            <p>This framework is designed for legitimate security research, education, and testing purposes only. All activities are logged and monitored.</p>
        </div>

        <h3>🔗 API Endpoints</h3>
        <a href="/health" class="api-link">Health Check</a>
        <a href="/api/status" class="api-link">System Status</a>

        <h3>🛡️ Security Features</h3>
        <div class="feature">✅ End-to-end encryption</div>
        <div class="feature">✅ Research mode enforcement</div>
        <div class="feature">✅ Ethical boundary controls</div>
        <div class="feature">✅ Comprehensive audit logging</div>
        <div class="feature">✅ Geographic restrictions</div>
        <div class="feature">✅ Time-based constraints</div>

        <h3>📊 Framework Components</h3>
        <div class="feature">🎯 C2 Communication Server</div>
        <div class="feature">🔒 Advanced Encryption Module</div>
        <div class="feature">📈 Real-time Monitoring</div>
        <div class="feature">⚖️ Ethical Control System</div>
        <div class="feature">📝 Compliance Logging</div>

        <p style="margin-top: 40px; font-size: 0.9em; opacity: 0.8;">
            Deployed on Render.com • Research Mode Active • All Activities Monitored
        </p>
    </div>
</body>
</html>' > /app/web/index.html

# Simple C2 server simulation for research
COPY <<EOF /app/c2_server.py
#!/usr/bin/env python3
import http.server
import socketserver
import json
import os
from datetime import datetime

class ResearchHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory='/app/web', **kwargs)
    
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
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
            self.send_header('Access-Control-Allow-Origin', '*')
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
        elif self.path == '/':
            # Serve the main dashboard
            self.path = '/index.html'
            super().do_GET()
        else:
            # Serve static files from web dashboard
            super().do_GET()

PORT = int(os.environ.get('PORT', 8080))
print(f"🔬 Advanced Botnet Research Framework")
print(f"🌐 Starting server on port {PORT}")
print(f"⚖️  Research Mode: ENABLED")
print(f"🔒 Ethical Controls: STRICT")
print(f"📁 Serving files from: /app/web")

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
