#!/bin/bash
set -e

echo "========================================="
echo "CyberSec Cheatsheet - Docker Startup"
echo "========================================="

echo ""
echo "Step 1: Waiting for PostgreSQL to be ready..."
until PGPASSWORD="postgres" psql -h postgres -U postgres -d cybersheet -c "\q" 2>/dev/null; do
  echo "  PostgreSQL is unavailable - sleeping"
  sleep 1
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
