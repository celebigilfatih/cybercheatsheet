# syntax=docker/dockerfile:1

# --- deps stage: install all dependencies (for build)
FROM node:18-bullseye-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

# --- builder stage: build Next.js app
FROM node:18-bullseye-slim AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

# --- runner stage: production runtime
FROM node:18-bullseye-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3311
ENV MONGODB_HOST=host.docker.internal
ENV MONGODB_PORT=33017
ENV MONGODB_DB=cybersheet
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Copy build output, public assets, scripts, and models
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/scripts ./scripts
COPY --from=builder /app/models ./models
COPY --from=builder /app/lib ./lib
COPY --from=builder /app/mdb ./mdb

EXPOSE 3311
CMD ["npm", "run", "start"]