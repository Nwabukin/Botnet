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

# Create the Python server file
RUN echo 'import http.server' > /app/server.py
RUN echo 'import socketserver' >> /app/server.py
RUN echo 'import json' >> /app/server.py
RUN echo 'import os' >> /app/server.py
RUN echo 'from datetime import datetime' >> /app/server.py
RUN echo '' >> /app/server.py
RUN echo 'class Handler(http.server.SimpleHTTPRequestHandler):' >> /app/server.py
RUN echo '    def __init__(self, *args, **kwargs):' >> /app/server.py
RUN echo '        super().__init__(*args, directory="/app/web", **kwargs)' >> /app/server.py
RUN echo '' >> /app/server.py
RUN echo '    def do_GET(self):' >> /app/server.py
RUN echo '        if self.path == "/health":' >> /app/server.py
RUN echo '            self.send_response(200)' >> /app/server.py
RUN echo '            self.send_header("Content-type", "application/json")' >> /app/server.py
RUN echo '            self.end_headers()' >> /app/server.py
RUN echo '            response = {"status": "healthy", "mode": "research"}' >> /app/server.py
RUN echo '            self.wfile.write(json.dumps(response).encode())' >> /app/server.py
RUN echo '        elif self.path == "/api/status":' >> /app/server.py
RUN echo '            self.send_response(200)' >> /app/server.py
RUN echo '            self.send_header("Content-type", "application/json")' >> /app/server.py
RUN echo '            self.end_headers()' >> /app/server.py
RUN echo '            response = {"framework": "Advanced Botnet Research Framework", "version": "1.0.0", "mode": "RESEARCH", "status": "operational"}' >> /app/server.py
RUN echo '            self.wfile.write(json.dumps(response).encode())' >> /app/server.py
RUN echo '        elif self.path == "/":' >> /app/server.py
RUN echo '            self.path = "/index.html"' >> /app/server.py
RUN echo '            super().do_GET()' >> /app/server.py
RUN echo '        else:' >> /app/server.py
RUN echo '            super().do_GET()' >> /app/server.py
RUN echo '' >> /app/server.py
RUN echo 'PORT = int(os.environ.get("PORT", 8080))' >> /app/server.py
RUN echo 'print(f"Starting server on port {PORT}")' >> /app/server.py
RUN echo 'with socketserver.TCPServer(("", PORT), Handler) as httpd:' >> /app/server.py
RUN echo '    httpd.serve_forever()' >> /app/server.py

# Create index.html
RUN echo '<!DOCTYPE html>' > /app/web/index.html
RUN echo '<html><head><title>Advanced Botnet Research Framework</title>' >> /app/web/index.html
RUN echo '<style>body{font-family:Arial;background:#1e3c72;color:white;text-align:center;padding:50px}' >> /app/web/index.html
RUN echo '.container{max-width:800px;margin:auto;background:rgba(0,0,0,0.3);padding:40px;border-radius:15px}' >> /app/web/index.html
RUN echo 'h1{color:#4CAF50;font-size:2.5em}.status{background:rgba(76,175,80,0.2);padding:20px;border-radius:10px;margin:20px 0}' >> /app/web/index.html
RUN echo '.api-link{background:#4CAF50;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;margin:10px;display:inline-block}' >> /app/web/index.html
RUN echo '.feature{background:rgba(255,255,255,0.1);padding:15px;margin:10px 0;border-radius:8px}</style></head>' >> /app/web/index.html
RUN echo '<body><div class="container"><h1>🔬 Advanced Botnet Research Framework</h1>' >> /app/web/index.html
RUN echo '<div class="status"><h2>✅ System Status: OPERATIONAL</h2>' >> /app/web/index.html
RUN echo '<p><strong>Mode:</strong> Research & Educational</p>' >> /app/web/index.html
RUN echo '<p><strong>Ethical Controls:</strong> STRICT</p></div>' >> /app/web/index.html
RUN echo '<h3>⚖️ RESEARCH USE ONLY</h3>' >> /app/web/index.html
RUN echo '<p>This framework is for legitimate security research and education only.</p>' >> /app/web/index.html
RUN echo '<h3>🔗 API Endpoints</h3>' >> /app/web/index.html
RUN echo '<a href="/health" class="api-link">Health Check</a>' >> /app/web/index.html
RUN echo '<a href="/api/status" class="api-link">System Status</a>' >> /app/web/index.html
RUN echo '<div class="feature">🎯 C2 Communication Server</div>' >> /app/web/index.html
RUN echo '<div class="feature">🔒 Advanced Encryption Module</div>' >> /app/web/index.html
RUN echo '<div class="feature">⚖️ Ethical Control System</div>' >> /app/web/index.html
RUN echo '<p style="margin-top:40px;opacity:0.8;">Deployed on Render.com • Research Mode Active</p>' >> /app/web/index.html
RUN echo '</div></body></html>' >> /app/web/index.html

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