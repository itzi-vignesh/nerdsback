import os
import sys
import django
import datetime
import subprocess
from pathlib import Path
from django.conf import settings

# Setup Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nerdslab.settings')
django.setup()

def create_backup():
    """Create a backup of the database and media files"""
    backup_dir = Path(settings.BACKUP_PATH)
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = backup_dir / f'backup_{timestamp}.sqlite3'
    
    # Backup database
    if settings.DATABASES['default']['ENGINE'] == 'django.db.backends.sqlite3':
        db_path = settings.DATABASES['default']['NAME']
        subprocess.run(['cp', db_path, str(backup_file)])
    
    # Backup media files
    media_backup = backup_dir / f'media_{timestamp}'
    if settings.MEDIA_ROOT:
        subprocess.run(['cp', '-r', settings.MEDIA_ROOT, str(media_backup)])
    
    # Cleanup old backups
    retention_days = getattr(settings, 'BACKUP_RETENTION_DAYS', 30)
    cutoff_date = datetime.datetime.now() - datetime.timedelta(days=retention_days)
    
    for backup in backup_dir.glob('backup_*.sqlite3'):
        backup_date = datetime.datetime.strptime(backup.stem.split('_')[1], '%Y%m%d_%H%M%S')
        if backup_date < cutoff_date:
            backup.unlink()
    
    for media_backup in backup_dir.glob('media_*'):
        backup_date = datetime.datetime.strptime(media_backup.stem.split('_')[1], '%Y%m%d_%H%M%S')
        if backup_date < cutoff_date:
            subprocess.run(['rm', '-rf', str(media_backup)])

if __name__ == '__main__':
    create_backup() 