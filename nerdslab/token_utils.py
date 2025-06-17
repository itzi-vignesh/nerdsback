import jwt
import uuid
from datetime import datetime, timedelta
from django.conf import settings
from django.core.cache import cache
import hashlib
import logging
from cryptography.fernet import Fernet
import base64
import os
import json

logger = logging.getLogger(__name__)

class TokenManager:
    def __init__(self):
        self.secret_key = settings.TOKEN_SETTINGS['SECRET_KEY']
        self.algorithm = settings.TOKEN_SETTINGS['ALGORITHM']
        self.access_token_lifetime = settings.TOKEN_SETTINGS['ACCESS_TOKEN_LIFETIME']
        self.refresh_token_lifetime = settings.TOKEN_SETTINGS['REFRESH_TOKEN_LIFETIME']
        # Initialize encryption key
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)

    def _get_or_create_encryption_key(self):
        """Get or create encryption key for token payload encryption."""
        key = cache.get('token_encryption_key')
        if not key:
            key = Fernet.generate_key()
            cache.set('token_encryption_key', key, timeout=None)  # Store indefinitely
        return key

    def _encrypt_payload(self, payload):
        """Encrypt token payload data."""
        # Convert payload to JSON and encrypt
        payload_json = json.dumps(payload)
        encrypted_data = self.cipher_suite.encrypt(payload_json.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()

    def _decrypt_payload(self, encrypted_data):
        """Decrypt token payload data."""
        try:
            # Decode and decrypt
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data)
            decrypted_data = self.cipher_suite.decrypt(encrypted_bytes)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            logger.error(f"Payload decryption failed: {str(e)}")
            raise jwt.InvalidTokenError('Invalid token payload')

    def generate_token_pair(self, user_id, username, email, role=None, token_type='lab', lab_id=None):
        """Generate access and refresh tokens with enhanced security."""
        token_id = str(uuid.uuid4())
        fingerprint = self._generate_fingerprint(user_id, username)
        
        # Create base payload
        base_payload = {
            'user_id': user_id,
            'username': username,
            'email': email,
            'role': role,
            'token_type': token_type,
            'token_id': token_id,
            'fingerprint': fingerprint,
            'iat': datetime.utcnow().timestamp(),
            'version': '1.0'
        }
        
        if lab_id:
            base_payload['lab_id'] = lab_id

        # Create access token with encrypted payload
        access_payload = base_payload.copy()
        access_payload['exp'] = (datetime.utcnow() + timedelta(seconds=self.access_token_lifetime)).timestamp()
        encrypted_access_payload = self._encrypt_payload(access_payload)
        
        # Create refresh token with encrypted payload
        refresh_payload = base_payload.copy()
        refresh_payload['token_type'] = 'refresh'
        refresh_payload['exp'] = (datetime.utcnow() + timedelta(seconds=self.refresh_token_lifetime)).timestamp()
        encrypted_refresh_payload = self._encrypt_payload(refresh_payload)
        
        # Sign tokens with encrypted payloads
        access_token = jwt.encode(
            {'data': encrypted_access_payload},
            self.secret_key,
            algorithm=self.algorithm
        )
        
        refresh_token = jwt.encode(
            {'data': encrypted_refresh_payload},
            self.secret_key,
            algorithm=self.algorithm
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
            token_data = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Decrypt payload
            payload = self._decrypt_payload(token_data['data'])
            
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

    def _generate_fingerprint(self, user_id, username):
        """Generate a unique fingerprint for the token."""
        # Add random entropy to fingerprint
        random_bytes = os.urandom(16)
        data = f"{user_id}:{username}:{datetime.utcnow().timestamp()}:{random_bytes.hex()}"
        return hashlib.sha256(data.encode()).hexdigest()

    def _store_fingerprint(self, fingerprint, user_id, token_id, lab_id=None):
        """Store token fingerprint and info in cache with encryption."""
        cache_key = f"token_fingerprint_{fingerprint}"
        data = {
            'user_id': user_id,
            'token_id': token_id,
            'lab_id': lab_id,
            'created_at': datetime.utcnow().timestamp()
        }
        # Encrypt fingerprint data
        encrypted_data = self._encrypt_payload(data)
        cache.set(cache_key, encrypted_data, timeout=self.access_token_lifetime)

    def _verify_fingerprint(self, fingerprint, user_id, token_id, lab_id=None):
        """Verify token fingerprint with encrypted data."""
        cache_key = f"token_fingerprint_{fingerprint}"
        encrypted_data = cache.get(cache_key)
        
        if not encrypted_data:
            return False
            
        try:
            stored_data = self._decrypt_payload(encrypted_data)
            return (
                stored_data['user_id'] == user_id and
                stored_data['token_id'] == token_id and
                (lab_id is None or stored_data['lab_id'] == lab_id)
            )
        except Exception:
            return False

    def _is_token_blacklisted(self, token_id):
        """Check if token is blacklisted."""
        return cache.get(f"token_blacklist_{token_id}") is not None

    def _verify_lab_access(self, user_id, lab_id, requested_url):
        """Verify user has access to the requested lab URL."""
        # Get user's active lab sessions
        cache_key = f"user_lab_sessions_{user_id}"
        encrypted_sessions = cache.get(cache_key)
        
        if not encrypted_sessions:
            return False
            
        try:
            user_sessions = self._decrypt_payload(encrypted_sessions)
            # Check if user has an active session for this lab
            for session in user_sessions:
                if (
                    session['lab_id'] == lab_id and
                    session['status'] in ['starting', 'running'] and
                    requested_url and
                    session['url'] in requested_url
                ):
                    return True
        except Exception:
            return False
                
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
        
        # Encrypt and store in cache
        encrypted_log = self._encrypt_payload(log_data)
        cache_key = f"access_log_{user_id}_{token_id}"
        cache.set(cache_key, encrypted_log, timeout=3600)  # Store for 1 hour
        
        # Log to system (with sensitive data redacted)
        safe_log_data = {**log_data}
        safe_log_data['user_agent'] = hashlib.sha256(user_agent.encode()).hexdigest() if user_agent else None
        safe_log_data['ip_address'] = hashlib.sha256(ip_address.encode()).hexdigest() if ip_address else None
        logger.info(f"Token access: {safe_log_data}")

# Create singleton instance
token_manager = TokenManager() 