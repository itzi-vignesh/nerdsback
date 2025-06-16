from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from django.conf import settings
from datetime import datetime, timedelta
import jwt
from typing import Dict, Any, Tuple

class SecureJWTAuthentication(JWTAuthentication):
    def get_validated_token(self, raw_token):
        try:
            # Decode and validate the token
            token = super().get_validated_token(raw_token)
            
            # Additional security checks
            if not self._verify_token_claims(token):
                raise InvalidToken('Token claims are invalid')
                
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
                
            return True
        except Exception:
            return False
            
    def _verify_token_fingerprint(self, claims: Dict[str, Any]) -> bool:
        """Verify token fingerprint to prevent token theft"""
        try:
            # Get stored fingerprint from user session
            stored_fingerprint = self._get_stored_fingerprint(claims.get('user_id'))
            
            # Compare with token fingerprint
            return stored_fingerprint == claims.get('fingerprint')
        except Exception:
            return False
            
    def _get_stored_fingerprint(self, user_id: int) -> str:
        """Get stored fingerprint from user session"""
        # Implement your fingerprint storage/retrieval logic here
        # This could be Redis, database, or other storage
        pass

def generate_tokens(user) -> Tuple[str, str]:
    """Generate secure access and refresh tokens"""
    # Generate refresh token
    refresh = RefreshToken.for_user(user)
    
    # Add custom claims
    refresh['token_type'] = 'refresh'
    refresh['token_version'] = settings.JWT_TOKEN_VERSION
    refresh['fingerprint'] = generate_token_fingerprint(user)
    
    # Generate access token
    access = refresh.access_token
    access['token_type'] = 'access'
    access['token_version'] = settings.JWT_TOKEN_VERSION
    access['fingerprint'] = generate_token_fingerprint(user)
    
    return str(access), str(refresh)

def generate_token_fingerprint(user) -> str:
    """Generate a unique fingerprint for the token"""
    # Combine user-specific data with a secret key
    data = f"{user.id}:{user.username}:{datetime.utcnow().timestamp()}"
    return jwt.encode(
        {'data': data},
        settings.SECRET_KEY,
        algorithm='HS256'
    )

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
    """Get stored fingerprint for user"""
    # Implement your fingerprint storage/retrieval logic here
    pass

def store_fingerprint(user_id: int, fingerprint: str) -> None:
    """Store fingerprint for user"""
    # Implement your fingerprint storage logic here
    pass 