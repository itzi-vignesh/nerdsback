from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from django.conf import settings
from django.core.cache import cache
from datetime import datetime, timedelta
import jwt
import hashlib
import os
from typing import Dict, Any, Tuple

class SecureJWTAuthentication(JWTAuthentication):
    def get_validated_token(self, raw_token):
        try:
            # Decode and validate the token
            token = super().get_validated_token(raw_token)
            
            # Additional security checks
            if not self._verify_token_claims(token):
                raise InvalidToken('Token claims are invalid')
                
            # Verify token hasn't been revoked
            if self._is_token_revoked(token):
                raise InvalidToken('Token has been revoked')
                
            return token
        except TokenError as e:
            raise InvalidToken(str(e))
            
    def _verify_token_claims(self, token) -> bool:
        """Verify additional security claims in the token"""
        try:
            # Get token claims
            claims = token.payload
            
            # Verify token type
            if claims.get('token_type') != 'access':
                return False
                
            # Verify token version (for future token invalidation)
            if claims.get('token_version') != settings.JWT_TOKEN_VERSION:
                return False
                
            # Verify token fingerprint
            if not self._verify_token_fingerprint(claims):
                return False
                
            # Verify token hasn't expired
            if datetime.utcfromtimestamp(claims.get('exp', 0)) < datetime.utcnow():
                return False
                
            return True
        except Exception:
            return False
            
    def _verify_token_fingerprint(self, claims: Dict[str, Any]) -> bool:
        """Verify token fingerprint to prevent token theft"""
        try:
            # Get stored fingerprint from cache
            stored_fingerprint = self._get_stored_fingerprint(claims.get('user_id'))
            
            # Compare with token fingerprint
            return stored_fingerprint == claims.get('fingerprint')
        except Exception:
            return False
            
    def _get_stored_fingerprint(self, user_id: int) -> str:
        """Get stored fingerprint from cache"""
        cache_key = f'user_fingerprint_{user_id}'
        return cache.get(cache_key)
        
    def _is_token_revoked(self, token) -> bool:
        """Check if token has been revoked"""
        jti = token.payload.get('jti')
        if not jti:
            return True
            
        # Check if token is in blacklist
        return cache.get(f'token_blacklist_{jti}') is not None

def generate_tokens(user) -> Tuple[str, str]:
    """Generate secure access and refresh tokens"""
    # Generate refresh token
    refresh = RefreshToken.for_user(user)
    
    # Generate fingerprint with additional entropy
    fingerprint = generate_token_fingerprint(user)
    
    # Store fingerprint in cache
    store_fingerprint(user.id, fingerprint)
    
    # Add custom claims
    refresh['token_type'] = 'refresh'
    refresh['token_version'] = settings.JWT_TOKEN_VERSION
    refresh['fingerprint'] = fingerprint
    refresh['jti'] = generate_jti()  # Add unique token ID
    
    # Generate access token
    access = refresh.access_token
    access['token_type'] = 'access'
    access['token_version'] = settings.JWT_TOKEN_VERSION
    access['fingerprint'] = fingerprint
    access['jti'] = generate_jti()  # Add unique token ID
    
    return str(access), str(refresh)

def generate_token_fingerprint(user) -> str:
    """Generate a unique fingerprint for the token"""
    # Generate random salt
    salt = os.urandom(16)
    
    # Combine user-specific data with salt and secret key
    data = f"{user.id}:{user.username}:{datetime.utcnow().timestamp()}"
    combined = f"{data}:{salt.hex()}:{settings.SECRET_KEY}"
    
    # Generate fingerprint using SHA-256
    return hashlib.sha256(combined.encode()).hexdigest()

def verify_token_fingerprint(token: str, user) -> bool:
    """Verify token fingerprint"""
    try:
        # Decode token
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=['HS256']
        )
        
        # Get stored fingerprint
        stored_fingerprint = get_stored_fingerprint(user.id)
        
        # Compare fingerprints
        return payload.get('fingerprint') == stored_fingerprint
    except Exception:
        return False

def get_stored_fingerprint(user_id: int) -> str:
    """Get stored fingerprint for user from cache"""
    cache_key = f'user_fingerprint_{user_id}'
    return cache.get(cache_key)

def store_fingerprint(user_id: int, fingerprint: str) -> None:
    """Store fingerprint for user in cache"""
    cache_key = f'user_fingerprint_{user_id}'
    # Store for 24 hours
    cache.set(cache_key, fingerprint, timeout=86400)

def generate_jti() -> str:
    """Generate a unique token ID"""
    return hashlib.sha256(os.urandom(32)).hexdigest()

def revoke_token(jti: str) -> None:
    """Revoke a token by adding it to the blacklist"""
    cache_key = f'token_blacklist_{jti}'
    # Blacklist for 24 hours
    cache.set(cache_key, True, timeout=86400) 