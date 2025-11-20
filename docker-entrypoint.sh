#!/bin/sh
set -e

# Install crontab
echo "Installing crontab..."
crontab /app/crontab

# Create cron log file
touch /app/reports/cron.log

# Print crontab for verification
echo "Crontab installed:"
crontab -l

# Start cron in background
echo "Starting cron daemon..."
crond -b -l 2

# Keep container running by tailing the cron log
echo "Cron daemon started. Tailing cron log..."
exec tail -f /app/reports/cron.log
