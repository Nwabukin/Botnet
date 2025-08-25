#!/bin/bash
set -e

# C2 Server Container Entry Point
# Handles initialization, health checks, and startup

echo "🚀 Starting C2 Server Container..."
echo "🔬 Research Mode: ${RESEARCH_MODE:-false}"
echo "📊 Environment: ${C2_MODE:-RESEARCH}"

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check if a service is ready
wait_for_service() {
    local host="$1"
    local port="$2"
    local service="$3"
    local timeout="${4:-60}"
    
    log "⏳ Waiting for $service at $host:$port..."
    
    for i in $(seq 1 $timeout); do
        if nc -z "$host" "$port" >/dev/null 2>&1; then
            log "✅ $service is ready!"
            return 0
        fi
        if [ $i -eq $timeout ]; then
            log "❌ Timeout waiting for $service"
            return 1
        fi
        sleep 1
    done
}

# Function to setup directories
setup_directories() {
    log "📁 Setting up directories..."
    
    mkdir -p /app/data/{bots,commands,logs,backups,temp}
    mkdir -p /app/logs
    mkdir -p /app/config
    
    # Ensure proper permissions
    chmod 755 /app/data /app/logs /app/config
    chmod 750 /app/data/{bots,commands,backups}
    chmod 1777 /app/data/temp  # Sticky bit for temp
    
    log "✅ Directories setup complete"
}

# Function to setup SSL certificates
setup_ssl_certificates() {
    log "🔐 Setting up SSL certificates..."
    
    if [ ! -f "/app/certs/server.crt" ] || [ ! -f "/app/certs/server.key" ]; then
        log "⚠️  SSL certificates not found, generating self-signed certificates for research..."
        
        # Generate private key
        openssl genrsa -out /app/certs/server.key 4096
        
        # Generate certificate signing request
        openssl req -new -key /app/certs/server.key -out /app/certs/server.csr -subj "/C=US/ST=Research/L=Lab/O=Security Research/OU=C2 Server/CN=c2-server"
        
        # Generate self-signed certificate
        openssl x509 -req -days 365 -in /app/certs/server.csr -signkey /app/certs/server.key -out /app/certs/server.crt
        
        # Generate Diffie-Hellman parameters
        openssl dhparam -out /app/certs/dhparam.pem 2048
        
        # Set proper permissions
        chmod 600 /app/certs/server.key
        chmod 644 /app/certs/server.crt /app/certs/dhparam.pem
        
        log "✅ Self-signed SSL certificates generated"
    else
        log "✅ SSL certificates already present"
    fi
}

# Function to validate research mode settings
validate_research_mode() {
    if [ "${RESEARCH_MODE}" = "true" ]; then
        log "🔬 Validating research mode configuration..."
        
        # Check required research environment variables
        if [ -z "${RESEARCH_SESSION_ID}" ]; then
            log "⚠️  RESEARCH_SESSION_ID not set, generating one..."
            export RESEARCH_SESSION_ID="research_$(date +%Y%m%d_%H%M%S)_$(hostname)"
        fi
        
        # Ensure ethical controls are enabled
        export ETHICAL_CONTROLS=strict
        export RESEARCH_LOGGING=verbose
        export COMPLIANCE_MODE=enabled
        
        log "✅ Research mode validated"
        log "🔬 Research Session ID: ${RESEARCH_SESSION_ID}"
    fi
}

# Function to wait for dependencies
wait_for_dependencies() {
    log "🔗 Checking dependencies..."
    
    # Wait for PostgreSQL
    if [ -n "${C2_DATABASE_URL}" ]; then
        local db_host=$(echo $C2_DATABASE_URL | sed -n 's/.*@\([^:]*\):.*/\1/p')
        local db_port=$(echo $C2_DATABASE_URL | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')
        wait_for_service "${db_host:-postgres}" "${db_port:-5432}" "PostgreSQL" 60
    fi
    
    # Wait for Redis
    if [ -n "${C2_REDIS_URL}" ]; then
        local redis_host=$(echo $C2_REDIS_URL | sed -n 's/.*:\/\/\([^:]*\):.*/\1/p')
        local redis_port=$(echo $C2_REDIS_URL | sed -n 's/.*:\([0-9]*\).*/\1/p')
        wait_for_service "${redis_host:-redis}" "${redis_port:-6379}" "Redis" 30
    fi
    
    log "✅ All dependencies are ready"
}

# Function to run database migrations
run_database_migrations() {
    log "🗄️  Running database migrations..."
    
    # Check if migration script exists
    if [ -f "/app/scripts/migrate.sh" ]; then
        /app/scripts/migrate.sh
        log "✅ Database migrations completed"
    else
        log "⚠️  No migration script found, skipping..."
    fi
}

# Function to setup monitoring
setup_monitoring() {
    if [ "${RESEARCH_MODE}" = "true" ]; then
        log "📊 Setting up research monitoring..."
        
        # Start monitoring tools in background
        if [ -f "/app/research-tools/monitor.sh" ]; then
            /app/research-tools/monitor.sh &
        fi
        
        # Setup audit logging
        if [ -f "/app/scripts/setup-audit.sh" ]; then
            /app/scripts/setup-audit.sh
        fi
        
        log "✅ Research monitoring setup complete"
    fi
}

# Function to perform health check
health_check() {
    log "🏥 Performing initial health check..."
    
    # Check if all required files exist
    local required_files=("/app/bin/c2_server" "/app/config/c2_server.conf")
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            log "❌ Required file missing: $file"
            exit 1
        fi
    done
    
    # Check SSL certificates
    if [ ! -f "/app/certs/server.crt" ] || [ ! -f "/app/certs/server.key" ]; then
        log "❌ SSL certificates missing"
        exit 1
    fi
    
    log "✅ Health check passed"
}

# Function to start the C2 server
start_c2_server() {
    log "🚀 Starting C2 Server..."
    
    # Set environment variables for the server
    export C2_CONFIG_FILE="/app/config/c2_server.conf"
    export C2_DATA_DIR="/app/data"
    export C2_LOG_DIR="/app/logs"
    export C2_CERT_DIR="/app/certs"
    export C2_WEB_DIR="/app/web"
    
    # Research mode specific settings
    if [ "${RESEARCH_MODE}" = "true" ]; then
        export C2_RESEARCH_MODE=true
        export C2_RESEARCH_SESSION_ID="${RESEARCH_SESSION_ID}"
        export C2_ETHICAL_CONTROLS=strict
        export C2_COMPLIANCE_LOGGING=enabled
    fi
    
    # Execute the C2 server
    exec /app/bin/c2_server \
        --config="/app/config/c2_server.conf" \
        --data-dir="/app/data" \
        --log-dir="/app/logs" \
        --web-dir="/app/web" \
        --cert-dir="/app/certs" \
        --research-mode="${RESEARCH_MODE:-false}" \
        --research-session="${RESEARCH_SESSION_ID:-}" \
        "$@"
}

# Function to handle shutdown signals
cleanup() {
    log "🛑 Shutting down C2 Server..."
    
    # Graceful shutdown
    if [ -n "$C2_PID" ]; then
        kill -TERM "$C2_PID" 2>/dev/null || true
        wait "$C2_PID" 2>/dev/null || true
    fi
    
    # Research mode cleanup
    if [ "${RESEARCH_MODE}" = "true" ]; then
        log "🔬 Performing research mode cleanup..."
        if [ -f "/app/scripts/research-cleanup.sh" ]; then
            /app/scripts/research-cleanup.sh
        fi
    fi
    
    log "✅ Shutdown complete"
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT

# Main execution flow
main() {
    log "🔄 Initializing C2 Server Container..."
    
    # Setup phase
    setup_directories
    setup_ssl_certificates
    validate_research_mode
    
    # Dependency phase
    wait_for_dependencies
    run_database_migrations
    
    # Monitoring phase
    setup_monitoring
    
    # Health check phase
    health_check
    
    # Startup phase
    log "✅ Initialization complete, starting C2 Server..."
    start_c2_server "$@"
}

# Execute main function
main "$@"
