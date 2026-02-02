# syntax=docker/dockerfile:1

# --- deps stage: install all dependencies (for build)
FROM node:20-bullseye-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

# --- builder stage: build Next.js app
FROM node:20-bullseye-slim AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

# --- runner stage: production runtime
FROM node:20-bullseye-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3311
# PostgreSQL connection settings
ENV DATABASE_URL="postgresql://postgres:postgres@postgres:5432/cybersheet?schema=public"
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Copy build output, public assets, scripts, prisma, and mdb
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/scripts ./scripts
COPY --from=builder /app/lib ./lib
COPY --from=builder /app/mdb ./mdb
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/public ./public

# Install PostgreSQL client for health checks
RUN apt-get update && apt-get install -y postgresql-client && rm -rf /var/lib/apt/lists/*

# Make entrypoint script executable
RUN chmod +x /app/scripts/docker-entrypoint.sh

EXPOSE 3311
ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]