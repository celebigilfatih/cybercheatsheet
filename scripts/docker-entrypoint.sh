#!/bin/bash
set -e

echo "========================================="
echo "CyberSec Cheatsheet - Docker Startup"
echo "========================================="

echo ""
echo "Step 1: Waiting for PostgreSQL to be ready..."

if [ -z "$DATABASE_URL" ]; then
  echo "ERROR: DATABASE_URL is not set"
  exit 1
fi

PG_HOST=$(echo "$DATABASE_URL" | sed -E 's/.*@([^:/]+).*/\1/')
echo "Connecting to PostgreSQL at $PG_HOST..."

until pg_isready -h "$PG_HOST" 2>/dev/null; do
  echo "  PostgreSQL is unavailable - sleeping"
  sleep 2
done
echo "✓ PostgreSQL is ready!"

echo ""
echo "Step 2: Running Prisma migrations..."
npm run prisma:generate
npm run prisma:push -- --skip-generate

echo ""
echo "Step 3: Migrating data from MongoDB to PostgreSQL..."
npm run migrate:postgres || echo "⚠ Migration script finished (may have already been run)"

echo ""
echo "Step 4: Starting the application..."
npm run start
