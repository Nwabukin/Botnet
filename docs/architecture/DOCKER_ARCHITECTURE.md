# Docker Container Architecture
## Containerized C2 Infrastructure Design

**Version**: 1.0  
**Date**: January 2025  
**Purpose**: Educational research infrastructure deployment

---

## 🐳 Container Orchestration Overview

The Docker architecture implements a **microservices approach** for the C2 infrastructure while keeping bot clients as **standalone executables**. This design ensures:

- **Scalability**: Each service can be scaled independently
- **Isolation**: Services are isolated for security and stability
- **Maintainability**: Easy updates and deployments
- **Monitoring**: Comprehensive observability stack

## 🏗️ Service Architecture

### **Core Services**

#### **1. C2 Main Server**
```dockerfile
# c2-server/docker/Dockerfile
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    g++ \
    cmake \
    libboost-all-dev \
    libssl-dev \
    libpq-dev \
    pkg-config

# Build application
WORKDIR /app
COPY . .
RUN mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc)

# Production stage
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    libboost-system1.74.0 \
    libboost-thread1.74.0 \
    libssl3 \
    libpq5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false c2server

WORKDIR /app
COPY --from=builder /app/build/c2-server .
COPY --from=builder /app/configs ./configs

# Set permissions
RUN chown -R c2server:c2server /app
USER c2server

EXPOSE 8443 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["./c2-server", "--config", "configs/production.json"]
```

#### **2. Web Dashboard**
```dockerfile
# c2-server/web-dashboard/Dockerfile
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

# Production stage
FROM nginx:1.24-alpine

# Copy built application
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Create non-root user
RUN addgroup -g 101 -S nginx && \
    adduser -S -D -H -u 101 -h /var/cache/nginx -s /sbin/nologin -G nginx -g nginx nginx

EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
```

### **Data Services**

#### **PostgreSQL Database**
```yaml
# Docker Compose PostgreSQL service
postgres:
  image: postgres:15-alpine
  container_name: botnet-postgres
  environment:
    POSTGRES_DB: ${DB_NAME}
    POSTGRES_USER: ${DB_USER}
    POSTGRES_PASSWORD: ${DB_PASSWORD}
    POSTGRES_INITDB_ARGS: "--auth-local=trust --auth-host=md5"
  volumes:
    - postgres_data:/var/lib/postgresql/data
    - ./c2-server/docker/postgres/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    - ./c2-server/docker/postgres/postgresql.conf:/etc/postgresql/postgresql.conf:ro
  networks:
    - c2-internal
  ports:
    - "5432:5432"
  restart: unless-stopped
  healthcheck:
    test: ["CMD-SHELL", "pg_isready -U ${DB_USER} -d ${DB_NAME}"]
    interval: 30s
    timeout: 10s
    retries: 3
    start_period: 40s
  security_opt:
    - no-new-privileges:true
  cap_drop:
    - ALL
  cap_add:
    - SETUID
    - SETGID
```

#### **Redis Cache**
```yaml
redis:
  image: redis:7-alpine
  container_name: botnet-redis
  command: >
    redis-server 
    --requirepass ${REDIS_PASSWORD}
    --maxmemory 256mb
    --maxmemory-policy allkeys-lru
    --save 900 1
    --save 300 10
    --save 60 10000
  volumes:
    - redis_data:/data
    - ./c2-server/docker/redis/redis.conf:/usr/local/etc/redis/redis.conf:ro
  networks:
    - c2-internal
  ports:
    - "6379:6379"
  restart: unless-stopped
  healthcheck:
    test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
    interval: 30s
    timeout: 3s
    retries: 3
  security_opt:
    - no-new-privileges:true
  cap_drop:
    - ALL
```

### **Monitoring Stack**

#### **Prometheus**
```yaml
prometheus:
  image: prom/prometheus:v2.45.0
  container_name: botnet-prometheus
  command:
    - '--config.file=/etc/prometheus/prometheus.yml'
    - '--storage.tsdb.path=/prometheus'
    - '--web.console.libraries=/etc/prometheus/console_libraries'
    - '--web.console.templates=/etc/prometheus/consoles'
    - '--storage.tsdb.retention.time=${PROMETHEUS_RETENTION:-200h}'
    - '--web.enable-lifecycle'
    - '--web.enable-admin-api'
  volumes:
    - ./tools/monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
    - ./tools/monitoring/rules:/etc/prometheus/rules:ro
    - prometheus_data:/prometheus
  networks:
    - monitoring
    - c2-internal
  ports:
    - "9090:9090"
  restart: unless-stopped
  healthcheck:
    test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:9090/-/healthy"]
    interval: 30s
    timeout: 10s
    retries: 3
  security_opt:
    - no-new-privileges:true
  cap_drop:
    - ALL
```

#### **Grafana**
```yaml
grafana:
  image: grafana/grafana:10.0.0
  container_name: botnet-grafana
  environment:
    - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
    - GF_USERS_ALLOW_SIGN_UP=false
    - GF_SECURITY_ALLOW_EMBEDDING=true
    - GF_AUTH_ANONYMOUS_ENABLED=false
    - GF_INSTALL_PLUGINS=grafana-clock-panel,grafana-simple-json-datasource
  volumes:
    - grafana_data:/var/lib/grafana
    - ./tools/monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
    - ./tools/monitoring/grafana/datasources:/etc/grafana/provisioning/datasources:ro
  networks:
    - monitoring
  ports:
    - "3001:3000"
  depends_on:
    - prometheus
  restart: unless-stopped
  healthcheck:
    test: ["CMD-SHELL", "curl -f localhost:3000/api/health"]
    interval: 30s
    timeout: 10s
    retries: 3
  security_opt:
    - no-new-privileges:true
  cap_drop:
    - ALL
```

---

## 🌐 Network Architecture

### **Network Segmentation**

```yaml
networks:
  # Internal C2 network (no external access)
  c2-internal:
    driver: bridge
    internal: true
    ipam:
      driver: default
      config:
        - subnet: 172.20.0.0/24
          gateway: 172.20.0.1
    driver_opts:
      com.docker.network.bridge.name: br-c2-internal
      com.docker.network.bridge.enable_icc: "true"
      com.docker.network.bridge.enable_ip_masquerade: "false"
  
  # External network for bot communication
  c2-external:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 172.21.0.0/24
          gateway: 172.21.0.1
    driver_opts:
      com.docker.network.bridge.name: br-c2-external
      com.docker.network.bridge.enable_icc: "true"
  
  # Monitoring network (isolated)
  monitoring:
    driver: bridge
    internal: true
    ipam:
      driver: default
      config:
        - subnet: 172.22.0.0/24
          gateway: 172.22.0.1
    driver_opts:
      com.docker.network.bridge.name: br-monitoring
  
  # Research network (controlled access)
  research:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 172.23.0.0/24
          gateway: 172.23.0.1
    driver_opts:
      com.docker.network.bridge.name: br-research
```

### **Service Network Mapping**

```yaml
# Network assignments for services
c2-server:
  networks:
    - c2-external   # Bot communication
    - c2-internal   # Database access
    - monitoring    # Metrics export

web-dashboard:
  networks:
    - c2-external   # User access
    - c2-internal   # API access

postgres:
  networks:
    - c2-internal   # Database access only

redis:
  networks:
    - c2-internal   # Cache access only

prometheus:
  networks:
    - monitoring    # Metrics collection
    - c2-internal   # Target scraping

grafana:
  networks:
    - monitoring    # Prometheus access
    - c2-external   # User dashboard access
```

### **Firewall Rules**

```yaml
# Docker daemon configuration for network security
{
  "iptables": true,
  "ip-forward": true,
  "userland-proxy": false,
  "experimental": false,
  "live-restore": true,
  "default-address-pools": [
    {
      "base": "172.20.0.0/16",
      "size": 24
    }
  ]
}
```

---

## 💾 Volume Management

### **Persistent Data Volumes**

```yaml
volumes:
  # Database data
  postgres_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: ${DATA_PATH}/postgres
  
  # Redis data
  redis_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: ${DATA_PATH}/redis
  
  # Research logs
  research_logs:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: ${RESEARCH_PATH}/logs
  
  # Configuration files
  config_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: ${CONFIG_PATH}
  
  # SSL certificates
  ssl_certs:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: ${CERTS_PATH}
  
  # Monitoring data
  prometheus_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: ${MONITORING_PATH}/prometheus
  
  grafana_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: ${MONITORING_PATH}/grafana
```

### **Backup Strategy**

```bash
#!/bin/bash
# Backup script for research data

BACKUP_DIR="/opt/botnet-research/backups"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "${BACKUP_DIR}/${DATE}"

# Backup PostgreSQL database
docker exec botnet-postgres pg_dump -U ${DB_USER} -d ${DB_NAME} > \
    "${BACKUP_DIR}/${DATE}/postgres_backup.sql"

# Backup Redis data
docker exec botnet-redis redis-cli --rdb /data/dump.rdb
docker cp botnet-redis:/data/dump.rdb "${BACKUP_DIR}/${DATE}/redis_backup.rdb"

# Backup configuration
cp -r /opt/botnet-research/config "${BACKUP_DIR}/${DATE}/"

# Backup research logs
tar -czf "${BACKUP_DIR}/${DATE}/research_logs.tar.gz" \
    /opt/botnet-research/logs/

# Encrypt backup
gpg --symmetric --cipher-algo AES256 --compress-algo 1 \
    --output "${BACKUP_DIR}/${DATE}_encrypted.gpg" \
    "${BACKUP_DIR}/${DATE}"

# Cleanup old backups (keep 30 days)
find "${BACKUP_DIR}" -type d -mtime +30 -exec rm -rf {} \;
```

---

## 🔧 Configuration Management

### **Environment Configuration**

```yaml
# .env file structure
# Database Configuration
DB_HOST=postgres
DB_PORT=5432
DB_NAME=botnet_research
DB_USER=botnet_user
DB_PASSWORD=${DB_PASSWORD}

# Redis Configuration
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=${REDIS_PASSWORD}

# C2 Server Configuration
C2_PORT=8443
C2_HTTP_PORT=8080
C2_DOMAIN=c2-server.research.local
C2_SSL_CERT=/certs/server.crt
C2_SSL_KEY=/certs/server.key

# Research Configuration
RESEARCH_MODE=true
ETHICAL_CONTROLS=enabled
MAX_CONNECTIONS=1000
SESSION_TIMEOUT=3600

# Monitoring Configuration
PROMETHEUS_RETENTION=200h
GRAFANA_PASSWORD=${GRAFANA_PASSWORD}
LOG_LEVEL=INFO

# Security Configuration
ENCRYPTION_KEY=${ENCRYPTION_KEY}
JWT_SECRET=${JWT_SECRET}
API_RATE_LIMIT=100

# Network Configuration
DOCKER_NETWORK_SUBNET=172.20.0.0/16
EXTERNAL_ACCESS=false
```

### **Service Configuration**

#### **C2 Server Configuration**
```json
{
  "server": {
    "bind_address": "0.0.0.0",
    "port": 8443,
    "http_port": 8080,
    "ssl_cert": "/certs/server.crt",
    "ssl_key": "/certs/server.key",
    "max_connections": 10000,
    "timeout_seconds": 30
  },
  "database": {
    "host": "postgres",
    "port": 5432,
    "database": "botnet_research",
    "username": "botnet_user",
    "password": "${DB_PASSWORD}",
    "pool_size": 20,
    "timeout_seconds": 10
  },
  "redis": {
    "host": "redis",
    "port": 6379,
    "password": "${REDIS_PASSWORD}",
    "database": 0,
    "timeout_seconds": 5
  },
  "research": {
    "enabled": true,
    "session_timeout_hours": 24,
    "max_bots_per_session": 100,
    "log_level": "INFO",
    "ethical_controls": true,
    "geographic_restrictions": ["US", "CA", "EU"]
  },
  "security": {
    "encryption_algorithm": "AES-256-GCM",
    "key_rotation_hours": 24,
    "certificate_validation": true,
    "rate_limiting": {
      "requests_per_minute": 60,
      "burst_size": 10
    }
  }
}
```

---

## 📊 Monitoring and Observability

### **Health Checks**

```yaml
# Health check configuration for all services
healthcheck_defaults: &healthcheck_defaults
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 30s

services:
  c2-server:
    healthcheck:
      <<: *healthcheck_defaults
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
  
  postgres:
    healthcheck:
      <<: *healthcheck_defaults
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER} -d ${DB_NAME}"]
      start_period: 40s
  
  redis:
    healthcheck:
      <<: *healthcheck_defaults
      test: ["CMD", "redis-cli", "ping"]
  
  web-dashboard:
    healthcheck:
      <<: *healthcheck_defaults
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
```

### **Metrics Collection**

```yaml
# Prometheus configuration
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "/etc/prometheus/rules/*.yml"

scrape_configs:
  # C2 Server metrics
  - job_name: 'c2-server'
    static_configs:
      - targets: ['c2-server:8080']
    metrics_path: '/metrics'
    scrape_interval: 15s
  
  # PostgreSQL metrics
  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:5432']
    metrics_path: '/metrics'
  
  # Redis metrics
  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']
  
  # Docker container metrics
  - job_name: 'docker'
    static_configs:
      - targets: ['host.docker.internal:9323']
```

### **Alerting Rules**

```yaml
# /etc/prometheus/rules/botnet_alerts.yml
groups:
  - name: botnet_research_alerts
    rules:
      # High bot connection rate
      - alert: HighBotConnectionRate
        expr: rate(botnet_connections_total[5m]) > 100
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High bot connection rate detected"
          description: "Bot connection rate is {{ $value }} connections/second"
      
      # Research session violations
      - alert: EthicalViolation
        expr: increase(botnet_ethical_violations_total[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Ethical violation detected"
          description: "Research ethical violation in session {{ $labels.session_id }}"
      
      # Database connection issues
      - alert: DatabaseDown
        expr: up{job="postgres"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "PostgreSQL database is down"
          description: "PostgreSQL database has been down for more than 1 minute"
      
      # Disk space warnings
      - alert: DiskSpaceHigh
        expr: (node_filesystem_avail_bytes / node_filesystem_size_bytes) * 100 < 20
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Low disk space"
          description: "Disk space is below 20% on {{ $labels.device }}"
```

---

## 🚀 Deployment Procedures

### **Development Deployment**

```bash
#!/bin/bash
# Development deployment script

set -e

echo "Starting development deployment..."

# Check prerequisites
if ! command -v docker &> /dev/null; then
    echo "Error: Docker not installed"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "Error: Docker Compose not installed"
    exit 1
fi

# Set up environment
cp env.example .env
echo "Please edit .env file with your configuration"
read -p "Press enter to continue after editing .env..."

# Create required directories
mkdir -p data/{postgres,redis} logs monitoring/{prometheus,grafana} certs config

# Generate SSL certificates for development
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key \
    -out certs/server.crt -days 365 -nodes \
    -subj "/C=US/ST=State/L=City/O=Research/CN=localhost"

# Build and start services
docker-compose build
docker-compose up -d

echo "Waiting for services to start..."
sleep 30

# Check service health
docker-compose ps
echo "Development environment ready!"
echo "C2 Server: https://localhost:8443"
echo "Dashboard: http://localhost:3000"
echo "Grafana: http://localhost:3001"
echo "Prometheus: http://localhost:9090"
```

### **Production Deployment**

```bash
#!/bin/bash
# Production deployment script

set -e

ENVIRONMENT="production"
BACKUP_RETENTION_DAYS=30

echo "Starting production deployment for botnet research infrastructure..."

# Validate environment
if [[ ! -f ".env.${ENVIRONMENT}" ]]; then
    echo "Error: .env.${ENVIRONMENT} file not found"
    exit 1
fi

# Load environment
source ".env.${ENVIRONMENT}"

# Security checks
if [[ "${DB_PASSWORD}" == "change_me" ]] || [[ "${REDIS_PASSWORD}" == "change_me" ]]; then
    echo "Error: Default passwords detected. Please update .env.${ENVIRONMENT}"
    exit 1
fi

# Backup existing data (if any)
if [[ -d "data" ]]; then
    echo "Creating backup of existing data..."
    tar -czf "backup_$(date +%Y%m%d_%H%M%S).tar.gz" data/
fi

# Deploy with production configuration
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Wait for services to stabilize
echo "Waiting for services to stabilize..."
timeout 300 bash -c 'until docker-compose ps | grep -q "Up"; do sleep 5; done'

# Verify deployment
./scripts/verify-deployment.sh

echo "Production deployment completed successfully!"
```

### **Scaling Configuration**

```yaml
# docker-compose.scale.yml
version: '3.8'

services:
  c2-server:
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      update_config:
        parallelism: 1
        delay: 10s
        failure_action: rollback
  
  postgres:
    deploy:
      resources:
        limits:
          cpus: '4.0'
          memory: 8G
        reservations:
          cpus: '2.0'
          memory: 4G
  
  redis:
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '1.0'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 1G
```

---

This Docker architecture provides a **robust, scalable, and secure foundation** for the C2 infrastructure while maintaining **clear separation** from the standalone bot clients. The design ensures **easy deployment, monitoring, and maintenance** while supporting the research objectives with proper **ethical controls and compliance mechanisms**.
