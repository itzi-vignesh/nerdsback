#!/bin/bash

# Configuration
DB_DIR="/var/www/nerdsback"
DB_FILE="$DB_DIR/db.sqlite3"
DB_USER="www-data"  # The user that Gunicorn runs as
DB_GROUP="www-data"

# Create database directory if it doesn't exist
sudo mkdir -p "$DB_DIR"

# Create database file if it doesn't exist
if [ ! -f "$DB_FILE" ]; then
    sudo touch "$DB_FILE"
fi

# Set correct ownership
sudo chown -R $DB_USER:$DB_GROUP "$DB_DIR"

# Set directory permissions (700 for directory)
sudo chmod 700 "$DB_DIR"

# Set database file permissions (600 for file)
sudo chmod 600 "$DB_FILE"

echo "Database directory and file permissions set up successfully"
echo "Directory: $(ls -ld $DB_DIR)"
echo "Database: $(ls -l $DB_FILE)"