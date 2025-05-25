#!/bin/bash

# Create necessary directories
mkdir -p logs media staticfiles

# Set up logging directories with proper permissions
mkdir -p logs
chmod 755 logs
touch logs/django.log
chmod 644 logs/django.log

# Set up SQLite database with proper permissions
DB_PATH="/var/www/nerdsback/db.sqlite3"
if [ ! -f "$DB_PATH" ]; then
    touch "$DB_PATH"
    if [ $? -eq 0 ]; then
        chmod 600 "$DB_PATH"
    else
        echo "Warning: Could not create database file. Please ensure the file exists with correct permissions."
    fi
fi

# Run migrations
python manage.py migrate --noinput

# Collect static files
python manage.py collectstatic --noinput

# Apply SQLite optimizations
sqlite3 "$DB_PATH" << EOF
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA temp_store = MEMORY;
PRAGMA mmap_size = 268435456;
PRAGMA cache_size = -64000;
PRAGMA busy_timeout = 30000;
EOF

# Start Gunicorn with optimized settings
exec gunicorn nerdslab.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 3 \
    --threads 4 \
    --worker-class gthread \
    --worker-tmp-dir /dev/shm \
    --max-requests 1000 \
    --max-requests-jitter 50 \
    --timeout 120 \
    --keepalive 75 \
    --log-level info \
    --access-logfile logs/access.log \
    --error-logfile logs/error.log