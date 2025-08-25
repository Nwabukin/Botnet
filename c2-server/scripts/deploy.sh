#!/bin/bash
# C2 Server Deployment Script
# Comprehensive deployment automation for research environment

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
DEPLOY_MODE="${1:-research}"
RESEARCH_SESSION_ID="${2:-research_$(date +%Y%m%d_%H%M%S)}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to log with timestamp and color
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")
            echo -e "${GREEN}[${timestamp}] INFO:${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[${timestamp}] WARN:${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[${timestamp}] ERROR:${NC} $message"
            ;;
        "DEBUG")
            echo -e "${BLUE}[${timestamp}] DEBUG:${NC} $message"
            ;;
        *)
            echo "[$timestamp] $level: $message"
            ;;
    esac
}

# Function to check prerequisites
check_prerequisites() {
    log "INFO" "🔍 Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker >/dev/null 2>&1; then
        log "ERROR" "Docker is not installed or not in PATH"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose >/dev/null 2>&1 && ! docker compose version >/dev/null 2>&1; then
        log "ERROR" "Docker Compose is not installed or not in PATH"
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info >/dev/null 2>&1; then
        log "ERROR" "Docker daemon is not running"
        exit 1
    fi
    
    # Check system resources
    local total_memory=$(free -m | awk 'NR==2{printf "%.0f", $2}')
    if [ "$total_memory" -lt 4096 ]; then
        log "WARN" "System has less than 4GB RAM ($total_memory MB). Performance may be impacted."
    fi
    
    local available_space=$(df "$PROJECT_ROOT" | tail -1 | awk '{print $4}')
    local available_gb=$((available_space / 1024 / 1024))
    if [ "$available_gb" -lt 10 ]; then
        log "WARN" "Less than 10GB disk space available ($available_gb GB). Consider freeing up space."
    fi
    
    log "INFO" "✅ Prerequisites check completed"
}

# Function to setup directories
setup_directories() {
    log "INFO" "📁 Setting up directory structure..."
    
    local dirs=(
        "data/c2-server"
        "data/c2-research"
        "data/postgres"
        "data/redis"
        "data/prometheus"
        "data/grafana"
        "data/elasticsearch"
        "logs/c2-server"
        "logs/c2-research"
        "backups/postgres"
        "configs/prometheus"
        "configs/grafana"
        "configs/elasticsearch"
        "configs/kibana"
        "configs/logstash"
        "configs/suricata"
        "configs/postgres"
        "configs/redis"
        "c2-server/docker/certs"
    )
    
    for dir in "${dirs[@]}"; do
        local full_path="$PROJECT_ROOT/$dir"
        if [ ! -d "$full_path" ]; then
            mkdir -p "$full_path"
            log "DEBUG" "Created directory: $full_path"
        fi
    done
    
    # Set proper permissions
    chmod 700 "$PROJECT_ROOT/data/postgres"
    chmod 755 "$PROJECT_ROOT/data/redis"
    chmod 755 "$PROJECT_ROOT/logs"/{c2-server,c2-research}
    chmod 750 "$PROJECT_ROOT/backups"
    
    log "INFO" "✅ Directory structure setup completed"
}

# Function to generate SSL certificates
generate_ssl_certificates() {
    log "INFO" "🔐 Generating SSL certificates..."
    
    local cert_dir="$PROJECT_ROOT/c2-server/docker/certs"
    
    if [ -f "$cert_dir/server.crt" ] && [ -f "$cert_dir/server.key" ]; then
        log "INFO" "SSL certificates already exist, skipping generation"
        return 0
    fi
    
    # Generate private key
    openssl genrsa -out "$cert_dir/server.key" 4096
    
    # Generate certificate signing request
    openssl req -new -key "$cert_dir/server.key" -out "$cert_dir/server.csr" \
        -subj "/C=US/ST=Research/L=Lab/O=Security Research/OU=C2 Server/CN=localhost" \
        -config <(cat <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Research
L = Lab
O = Security Research
OU = C2 Server
CN = localhost

[v3_req]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = c2-server
DNS.3 = *.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
)
    
    # Generate self-signed certificate
    openssl x509 -req -days 365 -in "$cert_dir/server.csr" \
        -signkey "$cert_dir/server.key" \
        -out "$cert_dir/server.crt" \
        -extensions v3_req \
        -extfile <(cat <<EOF
[v3_req]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = c2-server
DNS.3 = *.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
)
    
    # Generate Diffie-Hellman parameters
    openssl dhparam -out "$cert_dir/dhparam.pem" 2048
    
    # Set proper permissions
    chmod 600 "$cert_dir/server.key"
    chmod 644 "$cert_dir/server.crt" "$cert_dir/dhparam.pem"
    
    # Clean up CSR
    rm -f "$cert_dir/server.csr"
    
    log "INFO" "✅ SSL certificates generated successfully"
}

# Function to generate configuration files
generate_configurations() {
    log "INFO" "⚙️  Generating configuration files..."
    
    # Prometheus configuration
    cat > "$PROJECT_ROOT/configs/prometheus/prometheus.yml" <<EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules/*.yml"

scrape_configs:
  - job_name: 'c2-server'
    static_configs:
      - targets: ['c2-server:9090']
    scrape_interval: 10s
    metrics_path: '/metrics'

  - job_name: 'c2-research'
    static_configs:
      - targets: ['c2-server-research:9091']
    scrape_interval: 10s
    metrics_path: '/metrics'
    
  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['postgres:9187']
    scrape_interval: 30s

  - job_name: 'redis-exporter'
    static_configs:
      - targets: ['redis:9121']
    scrape_interval: 30s

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
    scrape_interval: 30s

alerting:
  alertmanagers:
    - static_configs:
        - targets: []
EOF

    # Grafana provisioning
    mkdir -p "$PROJECT_ROOT/configs/grafana/dashboards"
    mkdir -p "$PROJECT_ROOT/configs/grafana/datasources"
    
    cat > "$PROJECT_ROOT/configs/grafana/datasources/datasources.yml" <<EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
    
  - name: Elasticsearch
    type: elasticsearch
    access: proxy
    url: http://elasticsearch:9200
    database: "logstash-*"
    interval: Daily
    timeField: "@timestamp"
    editable: true
EOF

    # Logstash configuration
    cat > "$PROJECT_ROOT/configs/logstash/logstash.conf" <<EOF
input {
  file {
    path => "/logs/*.log"
    start_position => "beginning"
    codec => json
  }
  
  beats {
    port => 5044
  }
  
  tcp {
    port => 5000
    codec => json
  }
}

filter {
  if [fields][service] == "c2-server" {
    mutate {
      add_tag => ["c2-server"]
    }
  }
  
  if [fields][research_mode] == "true" {
    mutate {
      add_tag => ["research"]
      add_field => { "compliance_required" => "true" }
    }
  }
  
  # Parse timestamp
  date {
    match => [ "timestamp", "ISO8601" ]
  }
  
  # Anonymize sensitive data for research compliance
  if "research" in [tags] {
    mutate {
      remove_field => [ "password", "secret", "token", "key" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "c2-logs-%{+YYYY.MM.dd}"
  }
  
  # Research compliance logging
  if "research" in [tags] {
    file {
      path => "/logs/research-compliance.log"
      codec => json_lines
    }
  }
}
EOF

    # PostgreSQL initialization
    cat > "$PROJECT_ROOT/configs/postgres/01-init.sql" <<EOF
-- C2 Server Database Initialization
-- Research Environment Setup

-- Create research schema
CREATE SCHEMA IF NOT EXISTS research;

-- Create bot tracking table
CREATE TABLE IF NOT EXISTS research.bots (
    id SERIAL PRIMARY KEY,
    bot_id VARCHAR(64) UNIQUE NOT NULL,
    ip_address INET,
    hostname VARCHAR(255),
    operating_system VARCHAR(100),
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active',
    research_session_id VARCHAR(100),
    ethical_controls_enabled BOOLEAN DEFAULT true
);

-- Create command tracking table
CREATE TABLE IF NOT EXISTS research.commands (
    id SERIAL PRIMARY KEY,
    bot_id VARCHAR(64) REFERENCES research.bots(bot_id),
    command_type VARCHAR(50),
    command_data JSONB,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    execution_result JSONB,
    research_session_id VARCHAR(100),
    ethical_review_status VARCHAR(20) DEFAULT 'pending'
);

-- Create audit log table
CREATE TABLE IF NOT EXISTS research.audit_log (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50),
    event_data JSONB,
    user_id VARCHAR(100),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    research_session_id VARCHAR(100),
    compliance_level VARCHAR(20) DEFAULT 'standard'
);

-- Create research sessions table
CREATE TABLE IF NOT EXISTS research.sessions (
    session_id VARCHAR(100) PRIMARY KEY,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active',
    compliance_approved BOOLEAN DEFAULT false,
    ethical_review_completed BOOLEAN DEFAULT false
);

-- Insert initial research session
INSERT INTO research.sessions (session_id, description) 
VALUES ('${RESEARCH_SESSION_ID}', 'Docker deployment research session')
ON CONFLICT (session_id) DO NOTHING;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_bots_session ON research.bots(research_session_id);
CREATE INDEX IF NOT EXISTS idx_commands_session ON research.commands(research_session_id);
CREATE INDEX IF NOT EXISTS idx_audit_session ON research.audit_log(research_session_id);
CREATE INDEX IF NOT EXISTS idx_bots_last_seen ON research.bots(last_seen);

-- Grant permissions
GRANT ALL PRIVILEGES ON SCHEMA research TO botnet;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA research TO botnet;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA research TO botnet;
EOF

    log "INFO" "✅ Configuration files generated successfully"
}

# Function to build Docker images
build_images() {
    log "INFO" "🔨 Building Docker images..."
    
    cd "$PROJECT_ROOT"
    
    # Build C2 server image
    log "INFO" "Building C2 server image..."
    docker build -f c2-server/docker/Dockerfile -t botnet-c2:latest .
    
    # Build research variant
    log "INFO" "Building C2 research image..."
    docker build -f c2-server/docker/Dockerfile --target research -t botnet-c2:research .
    
    log "INFO" "✅ Docker images built successfully"
}

# Function to start services
start_services() {
    log "INFO" "🚀 Starting services in $DEPLOY_MODE mode..."
    
    cd "$PROJECT_ROOT"
    
    # Set environment variables
    export RESEARCH_SESSION_ID="$RESEARCH_SESSION_ID"
    export DEPLOY_MODE="$DEPLOY_MODE"
    
    case "$DEPLOY_MODE" in
        "production")
            docker-compose up -d c2-server postgres redis prometheus grafana
            ;;
        "research")
            docker-compose --profile research up -d
            ;;
        "security")
            docker-compose --profile research --profile security up -d
            ;;
        "maintenance")
            docker-compose --profile maintenance up -d backup logrotate
            ;;
        "full")
            docker-compose --profile research --profile security --profile maintenance up -d
            ;;
        *)
            log "ERROR" "Unknown deploy mode: $DEPLOY_MODE"
            exit 1
            ;;
    esac
    
    log "INFO" "✅ Services started successfully"
}

# Function to wait for services
wait_for_services() {
    log "INFO" "⏳ Waiting for services to be ready..."
    
    local max_wait=300  # 5 minutes
    local wait_time=0
    
    while [ $wait_time -lt $max_wait ]; do
        if docker-compose ps | grep -q "Up (healthy)"; then
            log "INFO" "✅ Services are healthy and ready"
            return 0
        fi
        
        if [ $((wait_time % 30)) -eq 0 ]; then
            log "INFO" "Still waiting for services... ($wait_time/$max_wait seconds)"
        fi
        
        sleep 5
        wait_time=$((wait_time + 5))
    done
    
    log "WARN" "Services may not be fully ready after $max_wait seconds"
    docker-compose ps
}

# Function to run post-deployment tests
run_post_deployment_tests() {
    log "INFO" "🧪 Running post-deployment tests..."
    
    # Test C2 server health
    if curl -f -s http://localhost:8080/health >/dev/null; then
        log "INFO" "✅ C2 server health check passed"
    else
        log "WARN" "❌ C2 server health check failed"
    fi
    
    # Test database connectivity
    if docker-compose exec -T postgres psql -U botnet -d botnet_research -c "SELECT 1;" >/dev/null 2>&1; then
        log "INFO" "✅ Database connectivity test passed"
    else
        log "WARN" "❌ Database connectivity test failed"
    fi
    
    # Test Redis connectivity
    if docker-compose exec -T redis redis-cli -a research_redis_2024 ping | grep -q PONG; then
        log "INFO" "✅ Redis connectivity test passed"
    else
        log "WARN" "❌ Redis connectivity test failed"
    fi
    
    # Test monitoring endpoints
    if [ "$DEPLOY_MODE" = "research" ] || [ "$DEPLOY_MODE" = "full" ]; then
        if curl -f -s http://localhost:9090/-/ready >/dev/null; then
            log "INFO" "✅ Prometheus health check passed"
        else
            log "WARN" "❌ Prometheus health check failed"
        fi
        
        if curl -f -s http://localhost:3000/api/health >/dev/null; then
            log "INFO" "✅ Grafana health check passed"
        else
            log "WARN" "❌ Grafana health check failed"
        fi
    fi
    
    log "INFO" "✅ Post-deployment tests completed"
}

# Function to display deployment information
show_deployment_info() {
    log "INFO" "📋 Deployment Information"
    echo ""
    echo "🔬 Research Session ID: $RESEARCH_SESSION_ID"
    echo "🚀 Deploy Mode: $DEPLOY_MODE"
    echo ""
    echo "🌐 Service URLs:"
    echo "  • C2 Server HTTP:  http://localhost:8080"
    echo "  • C2 Server HTTPS: https://localhost:8443"
    echo "  • C2 WebSocket:    ws://localhost:8081"
    echo "  • Admin Interface: http://localhost:9090"
    
    if [ "$DEPLOY_MODE" = "research" ] || [ "$DEPLOY_MODE" = "full" ]; then
        echo "  • Research C2:     http://localhost:8090"
        echo "  • Prometheus:      http://localhost:9090"
        echo "  • Grafana:         http://localhost:3000 (admin:research_grafana_2024)"
        echo "  • Kibana:          http://localhost:5601"
        echo "  • Elasticsearch:   http://localhost:9200"
    fi
    
    echo ""
    echo "📊 Database Connections:"
    echo "  • PostgreSQL:      localhost:5432 (botnet:research_password_2024)"
    echo "  • Redis:           localhost:6379 (password: research_redis_2024)"
    echo ""
    echo "📁 Data Directories:"
    echo "  • Data:    $PROJECT_ROOT/data/"
    echo "  • Logs:    $PROJECT_ROOT/logs/"
    echo "  • Backups: $PROJECT_ROOT/backups/"
    echo ""
    echo "🔐 SSL Certificates: $PROJECT_ROOT/c2-server/docker/certs/"
    echo ""
    echo "🛠️  Management Commands:"
    echo "  • Stop services:    docker-compose down"
    echo "  • View logs:        docker-compose logs -f [service]"
    echo "  • Restart service:  docker-compose restart [service]"
    echo "  • Scale service:    docker-compose up -d --scale [service]=[count]"
    echo ""
}

# Function to cleanup on failure
cleanup_on_failure() {
    log "ERROR" "Deployment failed, cleaning up..."
    docker-compose down --remove-orphans
    docker system prune -f
}

# Main deployment function
main() {
    log "INFO" "🚀 Starting C2 Server Deployment"
    log "INFO" "Mode: $DEPLOY_MODE"
    log "INFO" "Research Session: $RESEARCH_SESSION_ID"
    
    # Set error handling
    trap cleanup_on_failure ERR
    
    # Run deployment steps
    check_prerequisites
    setup_directories
    generate_ssl_certificates
    generate_configurations
    build_images
    start_services
    wait_for_services
    run_post_deployment_tests
    show_deployment_info
    
    log "INFO" "🎉 Deployment completed successfully!"
    log "INFO" "Research environment is ready for ethical security research"
}

# Handle command line arguments
case "${1:-}" in
    "help"|"-h"|"--help")
        echo "C2 Server Deployment Script"
        echo ""
        echo "Usage: $0 [MODE] [RESEARCH_SESSION_ID]"
        echo ""
        echo "Modes:"
        echo "  production  - Production deployment (minimal services)"
        echo "  research    - Research deployment (with monitoring and analysis tools)"
        echo "  security    - Security testing deployment (includes vulnerability scanners)"
        echo "  maintenance - Maintenance deployment (backup and cleanup services)"
        echo "  full        - Full deployment (all services and profiles)"
        echo ""
        echo "Examples:"
        echo "  $0 research"
        echo "  $0 research my_research_session_2024"
        echo "  $0 full research_advanced_2024"
        exit 0
        ;;
    "production"|"research"|"security"|"maintenance"|"full")
        main
        ;;
    "")
        main
        ;;
    *)
        log "ERROR" "Unknown mode: $1"
        log "INFO" "Use '$0 help' for usage information"
        exit 1
        ;;
esac
