import hmac
import hashlib
import base64
import json
from datetime import datetime, timedelta
from django.conf import settings
from typing import Dict, Optional

def generate_lab_token(username: str, lab_id: str, user_data: Dict) -> str:
    """
    Generate a secure lab token for a user-lab combination.
    
    Args:
        username: The username of the user
        lab_id: The ID of the lab
        user_data: Additional user data to include in the token
        
    Returns:
        A JWT-like token containing the user data and a signature
    """
    # Get the shared secret from settings
    secret = settings.LAB_SERVICE_TOKEN
    if not secret:
        raise ValueError("LAB_SERVICE_TOKEN not configured")

    # Create the payload
    now = datetime.utcnow()
    payload = {
        'username': username,
        'lab_id': lab_id,
        'user_id': user_data.get('userId'),
        'email': user_data.get('email'),
        'role': user_data.get('role'),
        'iat': now.timestamp(),  # Issued at
        'exp': (now + timedelta(hours=1)).timestamp(),  # Expires in 1 hour
    }

    # Convert payload to JSON and encode
    payload_json = json.dumps(payload, separators=(',', ':'))
    payload_bytes = payload_json.encode('utf-8')
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode('utf-8').rstrip('=')

    # Create signature using HMAC-SHA256
    signature = hmac.new(
        secret.encode('utf-8'),
        payload_b64.encode('utf-8'),
        hashlib.sha256
    ).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')

    # Combine payload and signature
    token = f"{payload_b64}.{signature_b64}"
    return token

def verify_lab_token(token: str) -> Optional[Dict]:
    """
    Verify a lab token and return the payload if valid.
    
    Args:
        token: The token to verify
        
    Returns:
        The token payload if valid, None otherwise
    """
    try:
        # Get the shared secret
        secret = settings.LAB_SERVICE_TOKEN
        if not secret:
            raise ValueError("LAB_SERVICE_TOKEN not configured")

        # Split token into payload and signature
        payload_b64, signature_b64 = token.split('.')
        
        # Add padding back to base64 strings
        payload_b64 += '=' * (4 - len(payload_b64) % 4)
        signature_b64 += '=' * (4 - len(signature_b64) % 4)

        # Verify signature
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            payload_b64.encode('utf-8'),
            hashlib.sha256
        ).digest()
        expected_signature_b64 = base64.urlsafe_b64encode(expected_signature).decode('utf-8').rstrip('=')

        if not hmac.compare_digest(signature_b64, expected_signature_b64):
            return None

        # Decode payload
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes.decode('utf-8'))

        # Check expiration
        if payload['exp'] < datetime.utcnow().timestamp():
            return None

        return payload

    except Exception as e:
        print(f"Error verifying lab token: {str(e)}")
        return None

def extract_user_info(token: str) -> Optional[Dict]:
    """
    Extract user information from a lab token without verification.
    This is useful for logging or non-critical operations.
    
    Args:
        token: The token to extract info from
        
    Returns:
        Basic user info if token is valid, None otherwise
    """
    try:
        payload_b64 = token.split('.')[0]
        payload_b64 += '=' * (4 - len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes.decode('utf-8'))
        
        return {
            'username': payload.get('username'),
            'lab_id': payload.get('lab_id'),
            'user_id': payload.get('user_id'),
            'email': payload.get('email'),
            'role': payload.get('role')
        }
    except Exception:
        return None 