#!/bin/bash
# Coolify Environment Variables Setup Script
# Run this on your Coolify server

echo "=== Coolify Environment Variables Setup ==="
echo ""

# Generate secure random values
JWT_SECRET=$(openssl rand -base64 48 | tr -d "=+/" | cut -c1-64)
ADMIN_PASS=$(openssl rand -base64 24 | tr -d "=+/" | cut -c1-32)
POSTGRES_PASSWORD=$(openssl rand -base64 24 | tr -d "=+/" | cut -c1-32)

echo "Generated secure passwords:"
echo "  JWT_SECRET: ${JWT_SECRET:0:20}..."
echo "  ADMIN_PASS: ${ADMIN_PASS:0:10}..."
echo "  POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:0:10}..."
echo ""

# Create environment file
cat > coolify-production.env << EOF
# ============================================
# CyberSec Cheatsheet - Production Environment
# ============================================

# Database Connection
# Format: postgresql://USER:PASSWORD@HOST:PORT/DATABASE?schema=public
# For Coolify internal network, use service name as host
DATABASE_URL=postgresql://postgres:${POSTGRES_PASSWORD}@postgres:5432/cybersheet?schema=public

# JWT Configuration
JWT_SECRET=${JWT_SECRET}

# Admin User Credentials
ADMIN_USER=admin
ADMIN_PASS=${ADMIN_PASS}

# Application Settings
PORT=3311
NODE_ENV=production
NEXT_TELEMETRY_DISABLED=1

# PostgreSQL Settings (for postgres service)
POSTGRES_USER=postgres
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DB=cybersheet

# Optional: Seed secret for database initialization
SEED_SECRET=$(openssl rand -base64 32)
EOF

echo "Environment file created: coolify-production.env"
echo ""
echo "=== NEXT STEPS ==="
echo "1. Copy these values to Coolify Dashboard:"
echo "   Project → Services → [Your Service] → Environment Variables"
echo ""
echo "2. Required variables to add:"
echo "   - DATABASE_URL"
echo "   - JWT_SECRET"
echo "   - ADMIN_USER"
echo "   - ADMIN_PASS"
echo "   - PORT"
echo "   - NODE_ENV"
echo ""
echo "3. Save and restart the service"
echo ""
echo "=== IMPORTANT ==="
echo "Save these credentials securely:"
echo ""
echo "Admin Login:"
echo "  Username: admin"
echo "  Password: ${ADMIN_PASS}"
echo ""
echo "PostgreSQL Password: ${POSTGRES_PASSWORD}"
echo ""
echo "Full .env file saved to: coolify-production.env"
