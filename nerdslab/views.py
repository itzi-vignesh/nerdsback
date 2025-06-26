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
    """Generate a new lab token."""
    try:
        logger.info(f"🎟️ Lab token generation request from user: {request.user.id} ({request.user.username})")
        logger.info(f"🎟️ Request data: {request.data}")
        logger.info(f"🎟️ Request headers: {dict(request.headers)}")
        
        lab_id = request.data.get('lab_id')
        if not lab_id:
            logger.warning(f"❌ Missing lab_id in request from user {request.user.username}")
            return Response({'error': 'lab_id is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        token = token_manager.generate_token_pair(
            user_id=request.user.id,
            username=request.user.username,
            email=request.user.email,
            role=request.user.role if hasattr(request.user, 'role') else None,
            token_type='lab',
            lab_id=lab_id
        )
        
        logger.info(f"✅ Lab token generated successfully for user {request.user.username}, lab {lab_id}")
        
        return Response({
            'access_token': token['access_token'],
            'refresh_token': token['refresh_token'],
            'lab_id': lab_id,
            'user_id': request.user.id
        })
    except Exception as e:
        logger.error(f"❌ Error generating lab token: {str(e)}", exc_info=True)
        return Response(
            {"error": "Failed to generate lab token"},
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
            
        # Verify refresh token
        payload = token_manager.verify_token(refresh_token)
        if not payload or payload.get('token_type') != 'refresh':
            return Response(
                {"error": "Invalid refresh token"},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        # Generate new token pair
        token = token_manager.generate_token_pair(
            user_id=request.user.id,
            username=request.user.username,
            email=request.user.email,
            role=request.user.role if hasattr(request.user, 'role') else None,
            token_type='lab',
            lab_id=payload.get('lab_id')
        )
        
        return Response({
            'access_token': token['access_token'],
            'refresh_token': token['refresh_token']
        })
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
            
        # Verify token
        payload = token_manager.verify_token(
            token,
            requested_url=request.data.get('requested_url'),
            user_agent=request.META.get('HTTP_USER_AGENT'),
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        if not payload:
            return Response(
                {"error": "Invalid token"},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        return Response({
            'user_id': payload['user_id'],
            'username': payload['username'],
            'email': payload.get('email'),
            'is_authenticated': True,
            'token_id': token,  # Add token_id for lab environment
            'lab_id': payload.get('lab_id'),
            'user_data': {
                'id': payload['user_id'],
                'username': payload['username'],
                'email': payload.get('email'),
            }
        })
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