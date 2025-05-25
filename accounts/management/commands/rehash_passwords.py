from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, identify_hasher
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Rehashes all user passwords using the stronger configured password hashers'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Run without making changes to the database',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        users = User.objects.all()
        self.stdout.write(f"Found {users.count()} users total")
        
        # Count of users that need rehashing
        need_rehash_count = 0
        rehashed_count = 0
        
        # Preferred hasher name
        preferred_hasher = 'argon2'
        
        for user in users:
            if not user.password or user.password.startswith('!'):
                # Skip users with unusable passwords
                continue
                
            try:
                # Get the hasher used for this password
                hasher = identify_hasher(user.password)
                # Check if a different hasher should be used
                if not hasher.__class__.__name__.lower().startswith(preferred_hasher):
                    need_rehash_count += 1
                    
                    if not dry_run:
                        # Get the password hash using the preferred hasher
                        # Note: We need the plaintext password to do this properly,
                        # but we don't have it, so this is just a placeholder.
                        # In reality, users would need to login, and the password would be
                        # rehashed at that time.
                        self.stdout.write(f"User {user.username} is using {hasher.__class__.__name__} hasher. "
                                         f"This would need to be rehashed to use {preferred_hasher}.")
                    
            except ValueError:
                self.stdout.write(self.style.WARNING(
                    f"User {user.username} has a password in an invalid format."
                ))
        
        self.stdout.write(self.style.SUCCESS(
            f"Found {need_rehash_count} users that would need password rehashing."
        ))
        
        if dry_run:
            self.stdout.write("Dry run completed. No changes were made.")
        else:
            self.stdout.write(f"Passwords will be rehashed when users log in next.")
            
        # Provide instructions for actual password rehashing
        self.stdout.write(self.style.NOTICE(
            "NOTE: Since we can't access plaintext passwords, users' passwords will be automatically "
            "rehashed to the new stronger algorithm when they next log in."
        )) 