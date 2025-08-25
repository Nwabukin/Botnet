#!/bin/bash
# C2 Server Health Check Script
# Comprehensive health validation for containerized environment

set -e

# Configuration
HEALTH_CHECK_TIMEOUT=10
C2_HTTP_PORT=${C2_HTTP_PORT:-8080}
C2_HTTPS_PORT=${C2_HTTPS_PORT:-8443}
C2_WEBSOCKET_PORT=${C2_WEBSOCKET_PORT:-8081}
C2_ADMIN_PORT=${C2_ADMIN_PORT:-9090}

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] HEALTH: $1"
}

# Function to check HTTP endpoint
check_http_endpoint() {
    local port="$1"
    local path="$2"
    local expected_status="$3"
    local protocol="${4:-http}"
    
    local url="${protocol}://localhost:${port}${path}"
    local status_code
    
    if command -v curl >/dev/null 2>&1; then
        status_code=$(curl -s -o /dev/null -w "%{http_code}" \
                          --connect-timeout $HEALTH_CHECK_TIMEOUT \
                          --max-time $HEALTH_CHECK_TIMEOUT \
                          --insecure \
                          "$url" 2>/dev/null || echo "000")
    else
        # Fallback to wget if curl is not available
        if wget -q --spider --timeout=$HEALTH_CHECK_TIMEOUT \
                 --no-check-certificate \
                 "$url" >/dev/null 2>&1; then
            status_code="200"
        else
            status_code="000"
        fi
    fi
    
    if [ "$status_code" = "$expected_status" ]; then
        return 0
    else
        log "❌ HTTP check failed: $url (got $status_code, expected $expected_status)"
        return 1
    fi
}

# Function to check TCP port
check_tcp_port() {
    local port="$1"
    local service="$2"
    
    if nc -z localhost "$port" >/dev/null 2>&1; then
        return 0
    else
        log "❌ TCP port check failed: $service on port $port"
        return 1
    fi
}

# Function to check process
check_process() {
    local process_name="$1"
    
    if pgrep -f "$process_name" >/dev/null 2>&1; then
        return 0
    else
        log "❌ Process check failed: $process_name not running"
        return 1
    fi
}

# Function to check file existence and permissions
check_file() {
    local file_path="$1"
    local required_permissions="$2"
    
    if [ ! -f "$file_path" ]; then
        log "❌ File check failed: $file_path does not exist"
        return 1
    fi
    
    if [ -n "$required_permissions" ]; then
        local actual_permissions=$(stat -c "%a" "$file_path" 2>/dev/null || echo "000")
        if [ "$actual_permissions" != "$required_permissions" ]; then
            log "⚠️  File permissions warning: $file_path has $actual_permissions, expected $required_permissions"
        fi
    fi
    
    return 0
}

# Function to check disk space
check_disk_space() {
    local path="$1"
    local min_free_mb="$2"
    
    local available_kb=$(df "$path" | tail -1 | awk '{print $4}')
    local available_mb=$((available_kb / 1024))
    
    if [ "$available_mb" -lt "$min_free_mb" ]; then
        log "❌ Disk space check failed: $path has ${available_mb}MB free, requires ${min_free_mb}MB"
        return 1
    fi
    
    return 0
}

# Function to check memory usage
check_memory_usage() {
    local max_usage_percent="$1"
    
    local memory_usage=$(free | grep Mem | awk '{print int($3/$2 * 100)}')
    
    if [ "$memory_usage" -gt "$max_usage_percent" ]; then
        log "⚠️  Memory usage warning: ${memory_usage}% (threshold: ${max_usage_percent}%)"
    fi
    
    return 0
}

# Function to check database connectivity
check_database() {
    if [ -n "${C2_DATABASE_URL}" ]; then
        local db_host=$(echo $C2_DATABASE_URL | sed -n 's/.*@\([^:]*\):.*/\1/p')
        local db_port=$(echo $C2_DATABASE_URL | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')
        
        if ! nc -z "${db_host:-postgres}" "${db_port:-5432}" >/dev/null 2>&1; then
            log "❌ Database connectivity check failed"
            return 1
        fi
    fi
    
    return 0
}

# Function to check Redis connectivity
check_redis() {
    if [ -n "${C2_REDIS_URL}" ]; then
        local redis_host=$(echo $C2_REDIS_URL | sed -n 's/.*:\/\/\([^:]*\):.*/\1/p')
        local redis_port=$(echo $C2_REDIS_URL | sed -n 's/.*:\([0-9]*\).*/\1/p')
        
        if ! nc -z "${redis_host:-redis}" "${redis_port:-6379}" >/dev/null 2>&1; then
            log "❌ Redis connectivity check failed"
            return 1
        fi
    fi
    
    return 0
}

# Function to check SSL certificates
check_ssl_certificates() {
    local cert_file="/app/certs/server.crt"
    local key_file="/app/certs/server.key"
    
    # Check certificate file
    if ! check_file "$cert_file" "644"; then
        return 1
    fi
    
    # Check key file
    if ! check_file "$key_file" "600"; then
        return 1
    fi
    
    # Check certificate validity
    if command -v openssl >/dev/null 2>&1; then
        local expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
        local expiry_timestamp=$(date -d "$expiry_date" +%s 2>/dev/null || echo "0")
        local current_timestamp=$(date +%s)
        local days_until_expiry=$(( (expiry_timestamp - current_timestamp) / 86400 ))
        
        if [ "$days_until_expiry" -lt 7 ]; then
            log "⚠️  SSL certificate expires in $days_until_expiry days"
        fi
        
        if [ "$expiry_timestamp" -le "$current_timestamp" ]; then
            log "❌ SSL certificate has expired"
            return 1
        fi
    fi
    
    return 0
}

# Function to perform research mode health checks
check_research_mode() {
    if [ "${RESEARCH_MODE}" = "true" ]; then
        log "🔬 Performing research mode health checks..."
        
        # Check research session ID
        if [ -z "${RESEARCH_SESSION_ID}" ]; then
            log "⚠️  Research session ID not set"
        fi
        
        # Check ethical controls
        if [ "${ETHICAL_CONTROLS}" != "strict" ]; then
            log "⚠️  Ethical controls not set to strict mode"
        fi
        
        # Check research logging
        if [ ! -f "/app/logs/research.log" ]; then
            log "⚠️  Research log file not found"
        fi
        
        # Check compliance settings
        if [ "${COMPLIANCE_MODE}" != "enabled" ]; then
            log "⚠️  Compliance mode not enabled"
        fi
    fi
    
    return 0
}

# Main health check function
main_health_check() {
    local exit_code=0
    
    log "🏥 Starting comprehensive health check..."
    
    # Check core processes
    if ! check_process "c2_server"; then
        exit_code=1
    fi
    
    # Check network ports
    if ! check_tcp_port "$C2_HTTP_PORT" "HTTP"; then
        exit_code=1
    fi
    
    if ! check_tcp_port "$C2_HTTPS_PORT" "HTTPS"; then
        exit_code=1
    fi
    
    if ! check_tcp_port "$C2_WEBSOCKET_PORT" "WebSocket"; then
        exit_code=1
    fi
    
    if ! check_tcp_port "$C2_ADMIN_PORT" "Admin"; then
        exit_code=1
    fi
    
    # Check HTTP endpoints
    if ! check_http_endpoint "$C2_HTTP_PORT" "/health" "200" "http"; then
        exit_code=1
    fi
    
    if ! check_http_endpoint "$C2_ADMIN_PORT" "/metrics" "200" "http"; then
        exit_code=1
    fi
    
    # Check essential files
    if ! check_file "/app/bin/c2_server" "755"; then
        exit_code=1
    fi
    
    if ! check_file "/app/config/c2_server.conf" "644"; then
        exit_code=1
    fi
    
    # Check SSL certificates
    if ! check_ssl_certificates; then
        exit_code=1
    fi
    
    # Check disk space (require at least 1GB free)
    if ! check_disk_space "/app/data" 1024; then
        exit_code=1
    fi
    
    # Check memory usage (warn if over 80%)
    check_memory_usage 80
    
    # Check external dependencies
    if ! check_database; then
        exit_code=1
    fi
    
    if ! check_redis; then
        exit_code=1
    fi
    
    # Research mode specific checks
    check_research_mode
    
    # Final status
    if [ $exit_code -eq 0 ]; then
        log "✅ All health checks passed"
    else
        log "❌ One or more health checks failed"
    fi
    
    return $exit_code
}

# Quick health check function (for faster checks)
quick_health_check() {
    local exit_code=0
    
    # Check if main process is running
    if ! check_process "c2_server"; then
        exit_code=1
    fi
    
    # Check if HTTP port is responding
    if ! check_tcp_port "$C2_HTTP_PORT" "HTTP"; then
        exit_code=1
    fi
    
    return $exit_code
}

# Deep health check function (comprehensive)
deep_health_check() {
    main_health_check
}

# Handle command line arguments
case "${1:-main}" in
    "quick")
        quick_health_check
        ;;
    "deep")
        deep_health_check
        ;;
    "main"|*)
        main_health_check
        ;;
esac

exit $?
