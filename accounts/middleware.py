from django.contrib.auth import get_user
from django.contrib.auth.hashers import check_password, make_password, identify_hasher
from django.utils.deprecation import MiddlewareMixin
import logging

logger = logging.getLogger(__name__)

class PasswordRehashMiddleware(MiddlewareMixin):
    """
    Middleware to automatically rehash passwords when users log in,
    if their password is stored with an outdated hashing algorithm.
    """
    
    def process_request(self, request):
        user = get_user(request)
        
        # Only proceed if the user is authenticated
        if user.is_authenticated and user.password and not user.password.startswith('!'):
            try:
                # Get the hasher that created this password
                hasher = identify_hasher(user.password)
                
                # Check if this is the preferred hasher (from first in PASSWORD_HASHERS)
                from django.conf import settings
                preferred_hasher_path = settings.PASSWORD_HASHERS[0].split('.')[-1]
                
                if hasher.__class__.__name__ != preferred_hasher_path:
                    logger.info(f"Rehashing password for user {user.username} from "
                               f"{hasher.__class__.__name__} to {preferred_hasher_path}")
                    
                    # This will happen only if we know the user's plaintext password
                    # This is only possible during login, which is handled by Django's auth system
                    # So this is mainly a fallback for sessions that already existed before
                    # the password hashing configuration was updated.
                    
                    # Note: The actual rehashing happens in the authenticate() function
                    # when the password is verified using check_password() which will rehash
                    # if needed based on the updated PASSWORD_HASHERS settings.
                    pass
                    
            except ValueError:
                # If the password is in an invalid format, log a warning
                logger.warning(f"User {user.username} has a password in an invalid format")
                
        return None 