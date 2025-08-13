#!/bin/bash

# EmailEngine Production Setup Script
# This script helps initialize a production-ready EmailEngine deployment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to generate secure random strings
generate_secret() {
    openssl rand -hex 32 2>/dev/null || cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1
}

generate_password() {
    openssl rand -base64 32 2>/dev/null || cat /dev/urandom | tr -dc 'a-zA-Z0-9!@#$%^&*()_+' | fold -w 32 | head -n 1
}

print_message $GREEN "==================================="
print_message $GREEN "EmailEngine Production Setup"
print_message $GREEN "==================================="
echo

# Check prerequisites
print_message $YELLOW "Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    print_message $RED "Error: Docker is not installed"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    print_message $RED "Error: Docker Compose is not installed"
    exit 1
fi

print_message $GREEN "✓ Prerequisites checked"
echo

# Check if docker-compose file exists
if [ ! -f "docker-compose.yml" ]; then
    print_message $RED "Error: docker-compose.yml not found"
    print_message $YELLOW "Please ensure you're running this script from the EmailEngine directory"
    exit 1
fi

# Create .env file if it doesn't exist
if [ -f ".env" ]; then
    print_message $YELLOW "Warning: .env file already exists"
    read -p "Do you want to overwrite it? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_message $YELLOW "Setup cancelled. Existing .env file preserved."
        exit 0
    fi
    # Backup existing .env
    cp .env .env.backup.$(date +%Y%m%d-%H%M%S)
    print_message $GREEN "✓ Existing .env backed up"
fi

print_message $YELLOW "Generating secure credentials..."

# Generate secure values
EENGINE_SECRET=$(generate_secret)
REDIS_PASSWORD=$(generate_password)
SMTP_PASSWORD=$(generate_password)

# Create .env file
cat > .env << EOF
# EmailEngine Production Environment Configuration
# Generated on $(date)

# ===========================================
# REQUIRED SECURITY SETTINGS
# ===========================================

# Encryption secret for EmailEngine
EENGINE_SECRET=${EENGINE_SECRET}

# Redis password
REDIS_PASSWORD=${REDIS_PASSWORD}

# Redis connection with authentication
EENGINE_REDIS=redis://:${REDIS_PASSWORD}@redis:6379/2

# ===========================================
# EMAILENGINE CONFIGURATION
# ===========================================

# Log level (error, warn, info, debug)
EENGINE_LOG_LEVEL=info

# Number of worker processes (adjust based on your CPU cores, min 4, max 24)
EENGINE_WORKERS=8

# EmailEngine settings (JSON format)
EENGINE_SETTINGS={"smtpServerEnabled": true, "smtpServerPort": 2525, "smtpServerHost": "0.0.0.0", "smtpServerAuthEnabled": true, "smtpServerPassword": "${SMTP_PASSWORD}"}

# ===========================================
# REDIS CONFIGURATION
# ===========================================

# Redis is used as a database - no memory limit, no eviction
# Monitor usage with: docker-compose exec redis redis-cli INFO memory
REDIS_LOG_LEVEL=notice

# ===========================================
# DATA PERSISTENCE
# ===========================================

# ===========================================
# SERVICE EXPOSURE (PRODUCTION)
# ===========================================

# Bind only to localhost for production
EMAILENGINE_API_BIND=127.0.0.1
EMAILENGINE_SMTP_BIND=127.0.0.1
EMAILENGINE_IMAP_BIND=127.0.0.1

# ===========================================
# HEALTH CHECKS
# ===========================================

# Use strict health checks for production
REDIS_HEALTHCHECK=service_healthy
HEALTHCHECK_INTERVAL=30s

# ===========================================
# OTHER SETTINGS
# ===========================================

RESTART_POLICY=unless-stopped
LOG_COMPRESS=true
EOF

print_message $GREEN "✓ .env file created with secure credentials"
echo

# Note about Redis data
print_message $YELLOW "Note: Redis data will be stored in a Docker volume"

print_message $GREEN "✓ Using unified docker-compose.yml with production settings"
echo

# Display credentials
print_message $GREEN "==================================="
print_message $GREEN "Setup Complete!"
print_message $GREEN "==================================="
echo
print_message $YELLOW "Important: Save these credentials securely!"
echo
echo "SMTP Password: ${SMTP_PASSWORD}"
echo
print_message $YELLOW "The encryption secret and Redis password have been"
print_message $YELLOW "securely stored in the .env file."
echo

# Offer to start services
read -p "Would you like to start EmailEngine now? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_message $YELLOW "Starting EmailEngine services..."
    docker-compose pull
    docker-compose up -d
    
    # Wait for services to start
    sleep 5
    
    # Check status
    if docker-compose ps | grep -q "Up"; then
        print_message $GREEN "✓ EmailEngine is running!"
        echo
        print_message $GREEN "Access the web interface at: http://localhost:3000"
        print_message $GREEN "SMTP server available at: localhost:2525"
        print_message $GREEN "IMAP proxy available at: localhost:9993"
        echo
        print_message $YELLOW "Default admin credentials:"
        echo "Username: admin"
        echo "Password: (not set - you'll be prompted to create one on first login)"
    else
        print_message $RED "Warning: Some services may not have started correctly"
        print_message $YELLOW "Check logs with: docker-compose logs"
    fi
else
    print_message $YELLOW "To start EmailEngine later, run:"
    echo "docker-compose up -d"
fi

echo
print_message $GREEN "For detailed deployment instructions, see DOCKER_DEPLOYMENT.md"