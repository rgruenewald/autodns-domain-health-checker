# Pin exact Node.js version for reproducible builds
FROM node:20.10.0-alpine

# Set working directory
WORKDIR /app

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

# Create reports directory with correct permissions
RUN mkdir -p reports && \
    chown -R nodejs:nodejs reports && \
    chmod 755 reports

# Switch to non-root user
USER nodejs

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "console.log('healthy')" || exit 1

# Expose no ports (runs as scheduled job)
# If adding API in future, uncomment and specify port
# EXPOSE 3000

# Run the application
CMD ["node", "src/index.js"]
