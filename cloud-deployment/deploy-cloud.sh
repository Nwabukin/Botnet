#!/bin/bash
# Cloud Deployment Script for Advanced Botnet Research Framework
# Supports multiple cloud platforms: Render, AWS, DigitalOcean, Railway

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="advanced-botnet-framework"
RESEARCH_SESSION_ID="cloud_deployment_$(date +%Y%m%d_%H%M%S)"

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
    esac
}

# Function to check prerequisites
check_prerequisites() {
    log "INFO" "🔍 Checking prerequisites for cloud deployment..."
    
    # Check required tools based on platform
    case "$1" in
        "render")
            if ! command -v git >/dev/null 2>&1; then
                log "ERROR" "Git is required for Render deployment"
                exit 1
            fi
            ;;
        "aws")
            if ! command -v aws >/dev/null 2>&1; then
                log "ERROR" "AWS CLI is required for AWS deployment"
                exit 1
            fi
            if ! command -v docker >/dev/null 2>&1; then
                log "ERROR" "Docker is required for AWS deployment"
                exit 1
            fi
            ;;
        "railway")
            if ! command -v railway >/dev/null 2>&1; then
                log "WARN" "Railway CLI not found. Install from: https://railway.app/cli"
                log "INFO" "You can also deploy via web interface"
            fi
            ;;
        "digitalocean")
            if ! command -v doctl >/dev/null 2>&1; then
                log "WARN" "DigitalOcean CLI not found. Install from: https://github.com/digitalocean/doctl"
            fi
            ;;
    esac
    
    log "INFO" "✅ Prerequisites check completed"
}

# Function to deploy to Render.com
deploy_render() {
    log "INFO" "🎯 Deploying to Render.com..."
    
    # Check if render.yaml exists
    if [ ! -f "cloud-deployment/render/render.yaml" ]; then
        log "ERROR" "render.yaml not found. Please ensure the file exists."
        exit 1
    fi
    
    log "INFO" "📋 Render Deployment Instructions:"
    echo ""
    echo "1. 🌐 Go to https://render.com and sign up/login"
    echo "2. 📁 Connect your GitHub repository"
    echo "3. 🔧 Import your project using the render.yaml file"
    echo "4. 🔒 Set up environment variables:"
    echo "   - RESEARCH_SESSION_ID: $RESEARCH_SESSION_ID"
    echo "   - RESEARCH_MODE: true"
    echo "   - ETHICAL_CONTROLS: strict"
    echo "5. 🚀 Deploy the services"
    echo ""
    echo "📝 Your render.yaml is configured with:"
    echo "   - C2 Server (Web Service)"
    echo "   - PostgreSQL Database"
    echo "   - Redis Cache"
    echo "   - Static Web Dashboard"
    echo ""
    echo "🔗 After deployment, access your services at:"
    echo "   - C2 Server: https://${PROJECT_NAME}-c2-server.onrender.com"
    echo "   - Dashboard: https://${PROJECT_NAME}-dashboard.onrender.com"
    echo ""
    
    log "INFO" "✅ Render deployment configuration ready!"
}

# Function to deploy to AWS
deploy_aws() {
    log "INFO" "☁️  Deploying to AWS..."
    
    local aws_region="${AWS_REGION:-us-east-1}"
    local stack_name="${PROJECT_NAME}-stack"
    
    # Check AWS credentials
    if ! aws sts get-caller-identity >/dev/null 2>&1; then
        log "ERROR" "AWS credentials not configured. Run 'aws configure' first."
        exit 1
    fi
    
    log "INFO" "🏗️  Creating CloudFormation stack..."
    
    # Deploy infrastructure
    aws cloudformation deploy \
        --template-file cloud-deployment/aws/cloudformation.yml \
        --stack-name "$stack_name" \
        --parameter-overrides \
            ProjectName="$PROJECT_NAME" \
            Environment="research" \
        --capabilities CAPABILITY_NAMED_IAM \
        --region "$aws_region"
    
    if [ $? -eq 0 ]; then
        log "INFO" "✅ CloudFormation stack deployed successfully"
        
        # Get stack outputs
        local alb_dns=$(aws cloudformation describe-stacks \
            --stack-name "$stack_name" \
            --region "$aws_region" \
            --query 'Stacks[0].Outputs[?OutputKey==`LoadBalancerDNS`].OutputValue' \
            --output text)
        
        log "INFO" "🌐 Your services will be available at:"
        echo "   - C2 Server: http://$alb_dns"
        echo "   - Dashboard: http://$alb_dns:3000"
        echo "   - Monitoring: http://$alb_dns:9090"
        
        # Build and push Docker image
        log "INFO" "🐳 Building and pushing Docker image..."
        
        local ecr_repo="${AWS_ACCOUNT_ID}.dkr.ecr.${aws_region}.amazonaws.com/${PROJECT_NAME}"
        
        # Create ECR repository if it doesn't exist
        aws ecr describe-repositories --repository-names "$PROJECT_NAME" --region "$aws_region" >/dev/null 2>&1 || \
        aws ecr create-repository --repository-name "$PROJECT_NAME" --region "$aws_region"
        
        # Login to ECR
        aws ecr get-login-password --region "$aws_region" | docker login --username AWS --password-stdin "$ecr_repo"
        
        # Build and push image
        docker build -f c2-server/docker/Dockerfile -t "$PROJECT_NAME:latest" .
        docker tag "$PROJECT_NAME:latest" "$ecr_repo:latest"
        docker push "$ecr_repo:latest"
        
        log "INFO" "✅ Docker image pushed to ECR"
        
        # Deploy ECS service
        log "INFO" "🚀 Deploying ECS service..."
        docker compose -f cloud-deployment/aws/docker-compose.aws.yml up -d
        
    else
        log "ERROR" "CloudFormation deployment failed"
        exit 1
    fi
    
    log "INFO" "✅ AWS deployment completed!"
}

# Function to deploy to Railway
deploy_railway() {
    log "INFO" "🚄 Deploying to Railway..."
    
    log "INFO" "📋 Railway Deployment Instructions:"
    echo ""
    echo "1. 🌐 Go to https://railway.app and sign up/login"
    echo "2. 📁 Connect your GitHub repository"
    echo "3. 🔧 Create a new project and import your repository"
    echo "4. 🔒 Set up environment variables in Railway dashboard:"
    echo "   - RESEARCH_SESSION_ID: $RESEARCH_SESSION_ID"
    echo "   - RESEARCH_MODE: true"
    echo "   - ETHICAL_CONTROLS: strict"
    echo "   - C2_DATABASE_URL: (Railway will provide PostgreSQL)"
    echo "   - C2_REDIS_URL: (Railway will provide Redis)"
    echo "5. 🚀 Deploy the services"
    echo ""
    echo "🔧 Railway will automatically:"
    echo "   - Detect Dockerfile and build your C2 server"
    echo "   - Provide managed PostgreSQL and Redis"
    echo "   - Set up networking between services"
    echo ""
    
    if command -v railway >/dev/null 2>&1; then
        log "INFO" "🚂 Railway CLI detected. You can also deploy using:"
        echo "   railway login"
        echo "   railway up"
    fi
    
    log "INFO" "✅ Railway deployment instructions provided!"
}

# Function to deploy to DigitalOcean App Platform
deploy_digitalocean() {
    log "INFO" "🌊 Deploying to DigitalOcean App Platform..."
    
    # Create DigitalOcean App Spec
    cat > .do/app.yaml <<EOF
name: ${PROJECT_NAME}
services:
- name: c2-server
  source_dir: /
  dockerfile_path: c2-server/docker/Dockerfile
  build_command: ""
  run_command: ""
  environment_slug: docker
  instance_count: 1
  instance_size_slug: basic-xxs
  http_port: 8080
  envs:
  - key: RESEARCH_MODE
    value: "true"
  - key: C2_MODE
    value: "RESEARCH"
  - key: ETHICAL_CONTROLS
    value: "strict"
  - key: COMPLIANCE_LOGGING
    value: "enabled"
  - key: C2_DATABASE_URL
    value: \${db.DATABASE_URL}
  - key: C2_REDIS_URL
    value: \${redis.DATABASE_URL}
  routes:
  - path: /

- name: web-dashboard
  source_dir: c2-server/web-dashboard
  build_command: echo "Static files ready"
  run_command: ""
  environment_slug: static
  routes:
  - path: /dashboard

databases:
- name: db
  engine: PG
  version: "15"
  size: basic-xs
  num_nodes: 1

- name: redis
  engine: REDIS
  version: "7"
  size: basic-xs
  num_nodes: 1
EOF

    log "INFO" "📋 DigitalOcean Deployment Instructions:"
    echo ""
    echo "1. 🌐 Go to https://cloud.digitalocean.com/apps and sign up/login"
    echo "2. 📁 Connect your GitHub repository"
    echo "3. 🔧 Import using the app.yaml file in .do/ directory"
    echo "4. 🚀 Deploy the application"
    echo ""
    echo "📝 App spec created with:"
    echo "   - C2 Server (Container)"
    echo "   - Web Dashboard (Static Site)"
    echo "   - PostgreSQL Database"
    echo "   - Redis Database"
    echo ""
    
    if command -v doctl >/dev/null 2>&1; then
        log "INFO" "🔧 DigitalOcean CLI detected. You can also deploy using:"
        echo "   doctl apps create .do/app.yaml"
    fi
    
    log "INFO" "✅ DigitalOcean app spec created!"
}

# Function to display general cloud deployment info
show_cloud_options() {
    log "INFO" "☁️  Advanced Botnet Research Framework - Cloud Deployment Options"
    echo ""
    echo "🎯 Choose your cloud platform:"
    echo ""
    echo "1. 🎨 Render.com (Recommended for beginners)"
    echo "   - Easy setup with render.yaml"
    echo "   - Automatic HTTPS"
    echo "   - Free tier available"
    echo "   - Command: ./cloud-deployment/deploy-cloud.sh render"
    echo ""
    echo "2. ☁️  AWS (Enterprise-grade)"
    echo "   - Full infrastructure control"
    echo "   - CloudFormation templates"
    echo "   - ECS/Fargate deployment"
    echo "   - Command: ./cloud-deployment/deploy-cloud.sh aws"
    echo ""
    echo "3. 🚄 Railway (Simple and fast)"
    echo "   - Git-based deployments"
    echo "   - Automatic scaling"
    echo "   - Integrated databases"
    echo "   - Command: ./cloud-deployment/deploy-cloud.sh railway"
    echo ""
    echo "4. 🌊 DigitalOcean App Platform"
    echo "   - Container-native platform"
    echo "   - Managed databases"
    echo "   - Cost-effective"
    echo "   - Command: ./cloud-deployment/deploy-cloud.sh digitalocean"
    echo ""
    echo "🔒 All deployments include:"
    echo "   ✅ Research mode enforcement"
    echo "   ✅ Ethical controls"
    echo "   ✅ Compliance logging"
    echo "   ✅ Monitoring and analytics"
    echo ""
}

# Function to create environment file
create_env_file() {
    cat > .env.cloud <<EOF
# Cloud Deployment Environment Variables
# Advanced Botnet Research Framework

# Research Configuration
RESEARCH_MODE=true
RESEARCH_SESSION_ID=${RESEARCH_SESSION_ID}
ETHICAL_CONTROLS=strict
COMPLIANCE_LOGGING=enabled

# Security Configuration
C2_ENCRYPTION_KEY=CHANGE_ME_32_CHAR_ENCRYPTION_KEY
JWT_SECRET=CHANGE_ME_JWT_SECRET_KEY_HERE
SSL_CERT_PATH=/app/certs/server.crt

# Database Configuration (Platform will provide)
C2_DATABASE_URL=postgresql://user:pass@host:5432/db
C2_REDIS_URL=redis://:pass@host:6379

# Server Configuration
C2_HTTP_PORT=8080
C2_HTTPS_PORT=8443
C2_WEBSOCKET_PORT=8081
C2_ADMIN_PORT=9090

# Monitoring Configuration
PROMETHEUS_ENABLED=true
GRAFANA_ADMIN_PASSWORD=CHANGE_ME_GRAFANA_PASSWORD
ELK_STACK_ENABLED=false

# Cloud Platform Specific
NODE_ENV=production
PORT=8080
EOF

    log "INFO" "📄 Environment file created: .env.cloud"
    log "WARN" "⚠️  Remember to update the CHANGE_ME values with secure passwords!"
}

# Main function
main() {
    local platform="${1:-help}"
    
    case "$platform" in
        "render")
            check_prerequisites "render"
            create_env_file
            deploy_render
            ;;
        "aws")
            check_prerequisites "aws"
            create_env_file
            deploy_aws
            ;;
        "railway")
            check_prerequisites "railway"
            create_env_file
            deploy_railway
            ;;
        "digitalocean"|"do")
            check_prerequisites "digitalocean"
            create_env_file
            deploy_digitalocean
            ;;
        "help"|*)
            show_cloud_options
            ;;
    esac
}

# Execute main function
main "$@"
