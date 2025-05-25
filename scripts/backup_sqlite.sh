#!/bin/bash

# Configuration
BACKUP_DIR="./backups/sqlite"
DB_FILE="db.sqlite3"
BACKUP_COUNT=7  # Keep last 7 days of backups

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Create backup filename with timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/db_backup_$TIMESTAMP.sqlite3"

# Wait for any write operations to finish
sqlite3 "$DB_FILE" "PRAGMA wal_checkpoint(FULL);"

# Create backup
sqlite3 "$DB_FILE" ".backup '$BACKUP_FILE'"

# Compress the backup
gzip "$BACKUP_FILE"

# Remove old backups (keep only last BACKUP_COUNT days)
find "$BACKUP_DIR" -name "db_backup_*.sqlite3.gz" -type f -mtime +$BACKUP_COUNT -delete

# Log the backup
echo "$(date): SQLite backup created: ${BACKUP_FILE}.gz" >> "$BACKUP_DIR/backup.log"