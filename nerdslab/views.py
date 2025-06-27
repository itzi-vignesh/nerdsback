from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.http import JsonResponse
import logging
from datetime import datetime

import psutil
import requests
import json

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authtoken.models import Token

from django_ratelimit.decorators import ratelimit

from .models import UserLab, UserLabProgress
from .utils import generate_lab_token, verify_lab_token, extract_user_info
from .token_utils import token_manager

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
#                       STATIC LAB‑TEMPLATE DEFINITIONS
# ---------------------------------------------------------------------------

LAB_TEMPLATES = [
    {
        "id": "mediconnect-lab",
        "track_id": "track-1",
        "module_id": "module-1",
        "name": "MediConnect Web Application Security",
        "description": (
            "Practice web security testing on a medical records management system. "
            "Learn to identify and exploit vulnerabilities in a healthcare application "
            "while understanding the importance of securing sensitive medical data."
        ),
        "difficulty": "medium",
        "category": "Web Security",
        "duration": 5400,  # 90 minutes in seconds
        "points_awarded": 250,
        "lab_type": "docker",
        "docker_image": "mediconnect_app",
        "tags": ["web", "security", "healthcare"],
        "is_locked": False,
    },
    {
        "id": "feedme-lab",
        "track_id": "track-1",
        "module_id": "module-1",
        "name": "FeedMe Social Media Security",
        "description": (
            "Explore social media application security by testing a vulnerable social "
            "networking platform. Practice identifying and exploiting common web "
            "vulnerabilities in a realistic environment."
        ),
        "difficulty": "medium",
        "category": "Web Security",
        "duration": 4500,  # 75 minutes in seconds
        "points_awarded": 200,
        "lab_type": "docker",
        "docker_image": "feedme_app",
        "tags": ["web", "security", "social-media"],
        "is_locked": False,
    },
]

# ---------------------------------------------------------------------------
#                               LAB FLAG / STATUS
# ---------------------------------------------------------------------------

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def verify_flag(request):
    """Verify lab flag submission."""
        
    lab_id = request.data.get("lab_id")
    flag = request.data.get("flag")

    if not lab_id or not flag:
        return Response(
            {"error": "Lab ID and flag are required"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        # Get user's lab progress
        user_lab = UserLab.objects.get(
            user=request.user,
            lab_id=lab_id
        )
        
        # Check if flag is correct
        is_correct = user_lab.verify_flag(flag)
        
        if is_correct:
            # Update progress
            UserLabProgress.objects.update_or_create(
                user=request.user,
                lab_id=lab_id,
                defaults={
                    'completed': True,
                    'completed_at': timezone.now()
                }
            )

            return Response({
                "status": "success",
                "message": "Flag verified successfully",
                "is_correct": True
            })
        else:
            return Response({
                "status": "error",
                "message": "Incorrect flag",
                "is_correct": False
            })
            
    except UserLab.DoesNotExist:
        return Response(
            {"error": "Lab not found or not assigned to user"},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.error(f"Error verifying flag: {str(e)}")
        return Response(
            {"error": "Failed to verify flag"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_lab_templates(request):
    return Response({
        "templates": LAB_TEMPLATES
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_lab_status(request):
    """Get user's lab progress."""
    try:
        progress = UserLabProgress.objects.filter(user=request.user)
        return Response([{
            'lab_id': p.lab_id,
            'completed': p.completed,
            'completed_at': p.completed_at,
            'last_attempt': p.last_attempt
        } for p in progress])
    except Exception as e:
        logger.error(f"Error getting lab status: {str(e)}")
        return Response(
            {"error": "Failed to get lab status"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

# ---------------------------------------------------------------------------
#                            HOUSE‑KEEPING ENDPOINTS
# ---------------------------------------------------------------------------

@require_http_methods(["GET"])
def health_check(request):
    return JsonResponse({"status": "healthy"})


@ratelimit(key="ip", rate="100/h", block=True)
@require_http_methods(["GET"])
def ratelimit_view(request):
    return JsonResponse({"status": "ok"})


# ---------------------------------------------------------------------------
#                           LAB TOKEN GENERATION API
# ---------------------------------------------------------------------------

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def generate_lab_token_view(request):
    """Generate a new lab token with modern JWT approach."""
    try:
        logger.info(f"🎟️ Lab token generation request from user: {request.user.id} ({request.user.username})")
        logger.info(f"🎟️ Request data: {request.data}")
        logger.info(f"🎟️ Request headers: {dict(request.headers)}")
        
        lab_id = request.data.get('lab_id')
        if not lab_id:
            logger.warning(f"❌ Missing lab_id in request from user {request.user.username}")
            return Response({'error': 'lab_id is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Generate modern JWT tokens with lab-specific claims
        from rest_framework_simplejwt.tokens import RefreshToken
        import uuid
        from datetime import datetime
        
        # Generate unique token IDs for lab context
        lab_access_token_id = str(uuid.uuid4())
        lab_refresh_token_id = str(uuid.uuid4())
        
        # Create refresh token with lab-specific claims
        refresh = RefreshToken.for_user(request.user)
        
        # Add lab-specific claims to access token
        refresh.access_token['jti'] = lab_access_token_id
        refresh.access_token['token_type'] = 'lab'
        refresh.access_token['context'] = 'lab'
        refresh.access_token['lab_id'] = lab_id
        refresh.access_token['user_id'] = request.user.id
        refresh.access_token['username'] = request.user.username
        refresh.access_token['email'] = request.user.email
        refresh.access_token['iat'] = datetime.utcnow().timestamp()
        
        # Add lab-specific claims to refresh token
        refresh['jti'] = lab_refresh_token_id
        refresh['token_type'] = 'lab_refresh'
        refresh['context'] = 'lab'
        refresh['lab_id'] = lab_id
        refresh['user_id'] = request.user.id
        refresh['username'] = request.user.username
        refresh['email'] = request.user.email
        refresh['iat'] = datetime.utcnow().timestamp()
        
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)
        
        logger.info(f"✅ Lab token generated successfully for user {request.user.username}, lab {lab_id}")
        logger.info(f"✅ Lab access token ID: {lab_access_token_id}")
        logger.info(f"✅ Lab refresh token ID: {lab_refresh_token_id}")
        
        return Response({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'lab_id': lab_id,
            'user_id': request.user.id,
            'token_info': {
                'access_token_id': lab_access_token_id,
                'refresh_token_id': lab_refresh_token_id,
                'context': 'lab',
                'expires_in': 3600,  # 1 hour for lab tokens
                'refresh_expires_in': 86400,  # 24 hours
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Lab token generation failed: {str(e)}", exc_info=True)
        return Response(
            {'error': 'Failed to generate lab token'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def refresh_lab_token_view(request):
    """Refresh an expired lab token."""
    try:
        refresh_token = request.data.get('refresh_token')
        if not refresh_token:
            return Response(
                {"error": "Refresh token is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Verify and decode the refresh token
        from rest_framework_simplejwt.tokens import RefreshToken
        from rest_framework_simplejwt.exceptions import InvalidToken
        
        try:
            refresh = RefreshToken(refresh_token)
            
            # Check if it's a lab token
            if refresh.get('token_type') != 'lab_refresh':
                return Response(
                    {"error": "Invalid lab refresh token"},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # Get lab_id from the refresh token
            lab_id = refresh.get('lab_id')
            if not lab_id:
                return Response(
                    {"error": "Lab ID not found in token"},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # Generate new token pair with lab-specific claims
            new_refresh = RefreshToken.for_user(request.user)
            
            # Add lab-specific claims to new access token
            new_refresh.access_token['lab_id'] = lab_id
            new_refresh.access_token['token_type'] = 'lab'
            new_refresh.access_token['context'] = 'lab'
            new_refresh.access_token['user_id'] = request.user.id
            new_refresh.access_token['username'] = request.user.username
            new_refresh.access_token['email'] = request.user.email
            
            # Add lab-specific claims to new refresh token
            new_refresh['lab_id'] = lab_id
            new_refresh['token_type'] = 'lab_refresh'
            new_refresh['context'] = 'lab'
            new_refresh['user_id'] = request.user.id
            new_refresh['username'] = request.user.username
            new_refresh['email'] = request.user.email
            
            return Response({
                'access_token': str(new_refresh.access_token),
                'refresh_token': str(new_refresh)
            })
            
        except InvalidToken:
            return Response(
                {"error": "Invalid refresh token"},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
    except Exception as e:
        logger.error(f"Error refreshing lab token: {str(e)}")
        return Response(
            {"error": "Failed to refresh lab token"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_lab_token_view(request):
    """Verify a lab token."""
    try:
        token = request.data.get('token')
        if not token:
            return Response(
                {"error": "Token is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Verify token using standard JWT
        from rest_framework_simplejwt.tokens import AccessToken
        from rest_framework_simplejwt.exceptions import InvalidToken
        
        try:
            access_token = AccessToken(token)
            
            # Check if it's a lab token
            if access_token.get('token_type') != 'lab':
                return Response(
                    {"error": "Invalid lab token"},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # Extract user information from token
            user_id = access_token.get('user_id')
            username = access_token.get('username')
            email = access_token.get('email')
            lab_id = access_token.get('lab_id')
            
            if not all([user_id, username, lab_id]):
                return Response(
                    {"error": "Invalid token payload"},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            return Response({
                'user_id': user_id,
                'username': username,
                'email': email,
                'is_authenticated': True,
                'token_id': access_token.get('jti'),  # JWT ID
                'lab_id': lab_id,
                'user_data': {
                    'id': user_id,
                    'username': username,
                    'email': email,
                }
            })
            
        except InvalidToken:
            return Response(
                {"error": "Invalid token"},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
    except Exception as e:
        logger.error(f"Error verifying lab token: {str(e)}")
        return Response(
            {"error": "Failed to verify lab token"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_lab_access(request):
    """
    Verify if a user has access to a specific lab.
    """
    try:
        user_id = request.data.get('user_id')
        lab_id = request.data.get('lab_id')
        
        if not user_id or not lab_id:
            return Response(
                {'error': 'user_id and lab_id are required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            from django.contrib.auth.models import User
            user = User.objects.get(id=user_id)
            # For now, allow all authenticated users to access labs
            # You can add more specific lab access logic here
            return Response({'has_access': True}, status=status.HTTP_200_OK)
            
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
            
    except Exception as e:
        logger.error(f"Lab access verification error: {str(e)}")
        return Response(
            {'error': 'Access verification failed'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def decrypt_frontend_data(request):
    """Decrypt frontend encrypted data for client use."""
    from .frontend_crypto import FrontendCrypto
    
    try:
        encrypted_data = request.data.get('encrypted_data')
        session_key = request.data.get('session_key')
        
        if not encrypted_data:
            return Response(
                {"error": "Encrypted data is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Decrypt the data
        crypto = FrontendCrypto()
        decrypted_data = crypto.decrypt_token_data(encrypted_data)
        
        if not decrypted_data:
            return Response(
                {"error": "Failed to decrypt data"},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        # Debug: Log the structure of decrypted data (without exposing sensitive content)
        logger.info(f"🔑 Decrypted data structure: {list(decrypted_data.keys()) if isinstance(decrypted_data, dict) else type(decrypted_data)}")
        if isinstance(decrypted_data, dict):
            token_keys = [k for k in decrypted_data.keys() if 'token' in k.lower()]
            user_keys = [k for k in decrypted_data.keys() if 'user' in k.lower()]
            logger.info(f"🔑 Token-related keys: {token_keys}")
            logger.info(f"🔑 User-related keys: {user_keys}")
            
        # Verify session key if provided
        if session_key:
            session_data = crypto.decrypt_token_data(session_key)
            if not session_data:
                logger.warning("Invalid session key provided")
        
        # Extract JWT tokens for API authentication
        access_token = decrypted_data.get('access')  # Frontend stores as 'access'
        refresh_token = decrypted_data.get('refresh')  # Frontend stores as 'refresh'
        auth_token = decrypted_data.get('auth_token')  # backward compatibility
        
        # Check if user data is nested or at root level
        user_data = decrypted_data.get('user')
        if not user_data:
            # User data might be at root level (for user_public data)
            if 'id' in decrypted_data and 'username' in decrypted_data:
                user_data = decrypted_data
            else:
                logger.warning("No user data found in decrypted data")
                user_data = {}
        
        # Prepare response with JWT tokens for frontend API authentication
        response_data = {
            "user": user_data,
            "tokens_available": bool(access_token or refresh_token or auth_token)
        }
        
        # Include JWT tokens if available
        if access_token:
            response_data["access"] = access_token
            logger.info("✅ Extracted access token from decrypted backend data")
        if refresh_token:
            response_data["refresh"] = refresh_token
            logger.info("✅ Extracted refresh token from decrypted backend data")
        if auth_token:
            response_data["auth_token"] = auth_token
            logger.info("✅ Extracted auth token from decrypted backend data (legacy)")
            
        # Log token extraction status for debugging
        logger.info(f"Token extraction: access={bool(access_token)}, refresh={bool(refresh_token)}, auth={bool(auth_token)}")
        
        return Response(response_data)
        
    except Exception as e:
        logger.error(f"Frontend decryption error: {str(e)}")
        return Response(
            {"error": "Decryption failed"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

# ---------------------------------------------------------------------------
#                           CONNECTIVITY TEST ENDPOINTS
# ---------------------------------------------------------------------------

@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def api_test_endpoint(request):
    """Simple test endpoint to verify API connectivity."""
    return Response({
        'status': 'success',
        'message': 'API is working correctly',
        'method': request.method,
        'timestamp': datetime.now().isoformat(),
        'cors_test': True,
        'data': request.data if request.method == 'POST' else None
    })

# ---------------------------------------------------------------------------