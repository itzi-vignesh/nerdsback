"""
Frontend Token Security and Encryption Utilities

This module provides secure token handling and data encryption 
for frontend applications to protect sensitive user information.
"""

import base64
import json
import os
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings
import hashlib
import logging

logger = logging.getLogger(__name__)

class FrontendCrypto:
    """
    Handles encryption/decryption of sensitive data for frontend storage.
    Uses strong encryption to protect tokens and user data in browser storage.
    """
    
    def __init__(self):
        self.master_key = self._get_master_key()
        self.cipher_suite = Fernet(self.master_key)
        
    def _get_master_key(self):
        """Generate or retrieve the master encryption key."""
        # Use a combination of secret key and environment-specific salt
        secret = settings.SECRET_KEY.encode()
        salt = os.environ.get('FRONTEND_CRYPTO_SALT', 'nerdslab-frontend-salt').encode()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(secret))
        return key
    
    def encrypt_token_data(self, token_data):
        """
        Encrypt token data for secure frontend storage.
        
        Args:
            token_data (dict): Token data including access_token, refresh_token, user_data
            
        Returns:
            str: Encrypted and base64 encoded token data
        """
        try:
            # Add timestamp and checksum for integrity
            token_data['encrypted_at'] = datetime.utcnow().isoformat()
            token_data['checksum'] = self._generate_checksum(token_data)
            
            # Convert to JSON and encrypt
            json_data = json.dumps(token_data, separators=(',', ':'))
            encrypted_data = self.cipher_suite.encrypt(json_data.encode())
            
            # Return base64 encoded for safe storage
            return base64.urlsafe_b64encode(encrypted_data).decode()
            
        except Exception as e:
            logger.error(f"Token encryption failed: {str(e)}")
            raise
    
    def decrypt_token_data(self, encrypted_token):
        """
        Decrypt token data from frontend storage.
        
        Args:
            encrypted_token (str): Base64 encoded encrypted token data
            
        Returns:
            dict: Decrypted token data or None if invalid
        """
        try:
            # Decode and decrypt
            encrypted_data = base64.urlsafe_b64decode(encrypted_token)
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            token_data = json.loads(decrypted_data.decode())
            
            # Verify checksum for integrity
            if not self._verify_checksum(token_data):
                raise ValueError("Token integrity check failed")
            
            # Check expiration (optional frontend-side check)
            encrypted_at = datetime.fromisoformat(token_data.get('encrypted_at', ''))
            if datetime.utcnow() - encrypted_at > timedelta(hours=24):
                logger.warning("Encrypted token is too old")
                
            return token_data
            
        except Exception as e:
            logger.error(f"Token decryption failed: {str(e)}")
            return None
    
    def _generate_checksum(self, data):
        """Generate checksum for data integrity verification."""
        # Create checksum from critical fields
        critical_data = {
            'access_token': data.get('access_token', ''),
            'user_id': data.get('user_data', {}).get('id', ''),
            'username': data.get('user_data', {}).get('username', '')
        }
        data_string = json.dumps(critical_data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(data_string.encode()).hexdigest()
    
    def _verify_checksum(self, data):
        """Verify data integrity using checksum."""
        stored_checksum = data.pop('checksum', '')
        calculated_checksum = self._generate_checksum(data)
        return stored_checksum == calculated_checksum
    
    def generate_frontend_session_key(self, user_id, session_data):
        """
        Generate a session-specific key for additional frontend security.
        
        Args:
            user_id (int): User ID
            session_data (dict): Session-specific data
            
        Returns:
            str: Encrypted session key
        """
        try:
            session_info = {
                'user_id': user_id,
                'session_id': session_data.get('session_id'),
                'ip_hash': hashlib.sha256(session_data.get('ip_address', '').encode()).hexdigest(),
                'user_agent_hash': hashlib.sha256(session_data.get('user_agent', '').encode()).hexdigest(),
                'created_at': datetime.utcnow().isoformat()
            }
            
            return self.encrypt_token_data(session_info)
            
        except Exception as e:
            logger.error(f"Session key generation failed: {str(e)}")
            raise
    
    def create_secure_storage_format(self, tokens, user_data, session_info):
        """
        Create a secure format for frontend storage.
        
        Args:
            tokens (dict): Access and refresh tokens
            user_data (dict): User information
            session_info (dict): Session information
            
        Returns:
            dict: Secure storage format with encrypted sensitive data
        """
        try:
            # Separate sensitive and non-sensitive data
            sensitive_data = {
                'access_token': tokens.get('access_token'),
                'refresh_token': tokens.get('refresh_token'),
                'auth_token': tokens.get('auth_token'),  # For backward compatibility
            }
            
            # Non-sensitive data (can be stored in plain text)
            non_sensitive_data = {
                'user_id': user_data.get('id'),
                'username': user_data.get('username'),
                'is_staff': user_data.get('is_staff', False),
                'login_time': datetime.utcnow().isoformat()
            }
            
            # Encrypt sensitive data
            encrypted_tokens = self.encrypt_token_data(sensitive_data)
            
            # Generate session key
            session_key = self.generate_frontend_session_key(
                user_data.get('id'), 
                session_info
            )
            
            return {
                'encrypted_tokens': encrypted_tokens,
                'session_key': session_key,
                'user_data': non_sensitive_data,
                'version': '1.0'
            }
            
        except Exception as e:
            logger.error(f"Secure storage format creation failed: {str(e)}")
            raise

# Global instance
frontend_crypto = FrontendCrypto()
