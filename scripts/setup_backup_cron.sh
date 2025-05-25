#!/bin/bash

# Get the absolute path of the project directory
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_SCRIPT="$PROJECT_DIR/scripts/backup.py"

# Create log directory if it doesn't exist
mkdir -p /var/log/nerdslab_backend

# Add cron job for daily backup at midnight
(crontab -l 2>/dev/null; echo "0 0 * * * cd $PROJECT_DIR && python $BACKUP_SCRIPT >> /var/log/nerdslab_backend/backup.log 2>&1") | crontab -

echo "Backup cron job has been set up successfully" 