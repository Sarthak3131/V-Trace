# Stage 1: Build
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .

# Stage 2: Production
FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --only=production
COPY --from=builder /app/src ./src
# Create uploads directory and set permissions for security hardening
RUN mkdir -p uploads && chown -R node:node /app
USER node
EXPOSE 5000
CMD ["node", "src/server.js"]
