import jwt
import uuid
from datetime import datetime, timedelta
from django.conf import settings
from django.core.cache import cache
import hashlib
import logging

logger = logging.getLogger(__name__)

class TokenManager:
    def __init__(self):
        self.secret_key = settings.TOKEN_SETTINGS['SECRET_KEY']
        self.algorithm = settings.TOKEN_SETTINGS['ALGORITHM']
        self.access_token_lifetime = settings.TOKEN_SETTINGS['ACCESS_TOKEN_LIFETIME']
        self.refresh_token_lifetime = settings.TOKEN_SETTINGS['REFRESH_TOKEN_LIFETIME']

    def generate_token_pair(self, user_id, username, email, role=None, token_type='lab', lab_id=None):
        """Generate access and refresh tokens with enhanced security."""
        token_id = str(uuid.uuid4())
        fingerprint = self._generate_fingerprint(user_id, username)
        
        # Create access token
        access_token = self._create_token(
            user_id=user_id,
            username=username,
            email=email,
            role=role,
            token_type=token_type,
            token_id=token_id,
            fingerprint=fingerprint,
            lab_id=lab_id,
            expires_in=self.access_token_lifetime
        )
        
        # Create refresh token
        refresh_token = self._create_token(
            user_id=user_id,
            username=username,
            email=email,
            role=role,
            token_type='refresh',
            token_id=token_id,
            fingerprint=fingerprint,
            lab_id=lab_id,
            expires_in=self.refresh_token_lifetime
        )
        
        # Store fingerprint and token info
        self._store_fingerprint(fingerprint, user_id, token_id, lab_id)
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_id': token_id,
            'fingerprint': fingerprint
        }

    def verify_token(self, token, requested_url=None, user_agent=None, ip_address=None):
        """Verify token with enhanced security checks."""
        try:
            # Decode token
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check token type
            if payload.get('token_type') != 'lab':
                raise jwt.InvalidTokenError('Invalid token type')
            
            # Verify fingerprint
            fingerprint = payload.get('fingerprint')
            if not self._verify_fingerprint(fingerprint, payload['user_id'], payload['token_id'], payload.get('lab_id')):
                raise jwt.InvalidTokenError('Invalid token fingerprint')
            
            # Check if token is blacklisted
            if self._is_token_blacklisted(payload['token_id']):
                raise jwt.InvalidTokenError('Token has been revoked')
            
            # Verify lab access if lab_id is present
            if payload.get('lab_id'):
                if not self._verify_lab_access(payload['user_id'], payload['lab_id'], requested_url):
                    raise jwt.InvalidTokenError('Invalid lab access')
            
            # Log access attempt
            self._log_access_attempt(
                user_id=payload['user_id'],
                token_id=payload['token_id'],
                requested_url=requested_url,
                user_agent=user_agent,
                ip_address=ip_address
            )
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise jwt.InvalidTokenError('Token has expired')
        except jwt.InvalidTokenError as e:
            raise e
        except Exception as e:
            logger.error(f"Token verification error: {str(e)}")
            raise jwt.InvalidTokenError('Token verification failed')

    def _create_token(self, user_id, username, email, role, token_type, token_id, fingerprint, lab_id=None, expires_in=3600):
        """Create a JWT token with enhanced security."""
        now = datetime.utcnow()
        payload = {
            'user_id': user_id,
            'username': username,
            'email': email,
            'role': role,
            'token_type': token_type,
            'token_id': token_id,
            'fingerprint': fingerprint,
            'iat': now,
            'exp': now + timedelta(seconds=expires_in),
            'version': '1.0'
        }
        
        if lab_id:
            payload['lab_id'] = lab_id
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def _generate_fingerprint(self, user_id, username):
        """Generate a unique fingerprint for the token."""
        data = f"{user_id}:{username}:{datetime.utcnow().timestamp()}"
        return hashlib.sha256(data.encode()).hexdigest()

    def _store_fingerprint(self, fingerprint, user_id, token_id, lab_id=None):
        """Store token fingerprint and info in cache."""
        cache_key = f"token_fingerprint_{fingerprint}"
        cache.set(cache_key, {
            'user_id': user_id,
            'token_id': token_id,
            'lab_id': lab_id,
            'created_at': datetime.utcnow().timestamp()
        }, timeout=self.access_token_lifetime)

    def _verify_fingerprint(self, fingerprint, user_id, token_id, lab_id=None):
        """Verify token fingerprint."""
        cache_key = f"token_fingerprint_{fingerprint}"
        stored_data = cache.get(cache_key)
        
        if not stored_data:
            return False
            
        return (
            stored_data['user_id'] == user_id and
            stored_data['token_id'] == token_id and
            (lab_id is None or stored_data['lab_id'] == lab_id)
        )

    def _is_token_blacklisted(self, token_id):
        """Check if token is blacklisted."""
        return cache.get(f"token_blacklist_{token_id}") is not None

    def _verify_lab_access(self, user_id, lab_id, requested_url):
        """Verify user has access to the requested lab URL."""
        # Get user's active lab sessions
        cache_key = f"user_lab_sessions_{user_id}"
        user_sessions = cache.get(cache_key)
        
        if not user_sessions:
            return False
            
        # Check if user has an active session for this lab
        for session in user_sessions:
            if (
                session['lab_id'] == lab_id and
                session['status'] in ['starting', 'running'] and
                requested_url and
                session['url'] in requested_url
            ):
                return True
                
        return False

    def _log_access_attempt(self, user_id, token_id, requested_url, user_agent, ip_address):
        """Log token access attempt for security monitoring."""
        log_data = {
            'user_id': user_id,
            'token_id': token_id,
            'requested_url': requested_url,
            'user_agent': user_agent,
            'ip_address': ip_address,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Store in cache for recent access history
        cache_key = f"access_log_{user_id}_{token_id}"
        cache.set(cache_key, log_data, timeout=3600)  # Store for 1 hour
        
        # Log to system
        logger.info(f"Token access: {log_data}")

# Create singleton instance
token_manager = TokenManager() 