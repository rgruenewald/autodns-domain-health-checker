# Pin exact Node.js version for reproducible builds
FROM node:20.10.0-alpine

# Set working directory
WORKDIR /app

# Install cron
RUN apk add --no-cache dcron

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --omit=dev && \
    npm cache clean --force

# Copy application files with correct ownership
COPY --chown=nodejs:nodejs src/ ./src/
COPY --chown=nodejs:nodejs dkim.config.json ./

# Copy cron configuration and entrypoint script
COPY --chown=root:root crontab /app/crontab
COPY --chown=root:root docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod 0644 /app/crontab && \
    chmod +x /app/docker-entrypoint.sh

# Create reports directory with correct permissions
RUN mkdir -p reports && \
    chown -R nodejs:nodejs reports && \
    chmod 755 reports

# Note: We stay as root to run cron daemon
# The cron jobs will run as root but could be configured to run as nodejs user if needed

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "console.log('healthy')" || exit 1

# Expose no ports (runs as scheduled job)
# If adding API in future, uncomment and specify port
# EXPOSE 3000

# Use entrypoint script to set up and run cron
ENTRYPOINT ["/app/docker-entrypoint.sh"]
