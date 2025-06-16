from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.http import JsonResponse
import logging

import psutil
import requests
import json

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authtoken.models import Token

from django_ratelimit.decorators import ratelimit

from .models import LabFlag, LabSubmission
from accounts.models import UserLab, UserLabProgress
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
        "title": "MediConnect Web Application Security",
        "description": (
            "Practice web security testing on a medical records management system. "
            "Learn to identify and exploit vulnerabilities in a healthcare application "
            "while understanding the importance of securing sensitive medical data."
        ),
        "difficulty": "medium",
        "category": "Web Security",
        "estimated_minutes": 90,
        "points_awarded": 250,
        "lab_type": "docker",
        "docker_image": "mediconnect_app",
    },
    {
        "id": "feedme-lab",
        "track_id": "track-1",
        "module_id": "module-1",
        "title": "FeedMe Social Media Security",
        "description": (
            "Explore social media application security by testing a vulnerable social "
            "networking platform. Practice identifying and exploiting common web "
            "vulnerabilities in a realistic environment."
        ),
        "difficulty": "medium",
        "category": "Web Security",
        "estimated_minutes": 75,
        "points_awarded": 200,
        "lab_type": "docker",
        "docker_image": "feedme_app",
    },
]

# ---------------------------------------------------------------------------
#                                 AUTH VIEWS
# ---------------------------------------------------------------------------

@csrf_exempt
@require_http_methods(["POST"])
@api_view(["POST"])
@permission_classes([AllowAny])
def login_handler(request):
    """Custom login endpoint returning both auth and lab tokens + basic user data."""

    username = request.data.get("username")
    password = request.data.get("password")

    if not username or not password:
        return Response(
            {"error": "Username and password are required"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    user = authenticate(username=username, password=password)

    if user is None:
        return Response(
            {"error": "Invalid credentials"},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    if not user.is_active:
        return Response(
            {"error": "User account is disabled"},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    # Generate authentication token
    auth_token, _ = Token.objects.get_or_create(user=user)

    # Generate lab token
    try:
        lab_token = token_manager.generate_token_pair(
            user_id=user.id,
            username=user.username,
            email=user.email,
            role=user.role if hasattr(user, 'role') else None,
            token_type='lab'
        )
    except Exception as e:
        logger.error(f"Failed to generate lab token: {str(e)}")
        return Response(
            {"error": "Failed to generate lab token"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    user_data = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "is_staff": user.is_staff,
        "is_superuser": user.is_superuser,
    }

    return Response({
        "auth_token": auth_token.key,
        "lab_token": lab_token['access_token'],
        "lab_refresh_token": lab_token['refresh_token'],
        "user": user_data
    })

# ---------------------------------------------------------------------------
#                               LAB FLAG / STATUS
# ---------------------------------------------------------------------------

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def verify_flag(request):
    """Very naïve flag‑verification placeholder."""
        
    lab_id = request.data.get("lab_id")
    flag = request.data.get("flag")

    if not lab_id or not flag:
        return Response(
            {"error": "Lab ID and flag are required"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # TODO: real check
    return Response(
        {
            "status": "success",
            "message": "Flag verified successfully",
            "is_correct": True,
        }
    )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_lab_templates(request):
    return Response(LAB_TEMPLATES)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_lab_status(request):
    """Placeholder – should return progress for current user."""

    return Response([])

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
    """
    Generate a lab token for a user-lab combination.
    This token will be used by the lab environment to verify the user.
    """
    try:
        # Get required data from request
        lab_id = request.data.get('lab_id')
        user_data = request.data.get('user_data', {})

        if not lab_id:
            return Response({
                'error': 'Lab ID is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Prepare user data
        user_data.update({
            'id': request.user.id,
            'username': request.user.username,
            'email': request.user.email,
            'role': request.user.role if hasattr(request.user, 'role') else None,
            'lab_id': lab_id
        })

        # Generate token pair
        access_token, refresh_token = token_manager.generate_token_pair(user_data)

        logger.info(f"Generated lab token for user {request.user.username} and lab {lab_id}")

        return Response({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': 3600  # 1 hour in seconds
        })

    except ValueError as e:
        logger.error(f"Error generating lab token: {str(e)}")
        return Response({
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except Exception as e:
        logger.error(f"Unexpected error generating lab token: {str(e)}")
        return Response({
            'error': 'Failed to generate lab token'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def refresh_lab_token_view(request):
    """
    Refresh a lab token using a refresh token.
    """
    try:
        refresh_token = request.data.get('refresh_token')
        if not refresh_token:
            return Response({
                'error': 'Refresh token is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Generate new token pair
        tokens = token_manager.refresh_token(refresh_token)
        if not tokens:
            return Response({
                'error': 'Invalid refresh token'
            }, status=status.HTTP_401_UNAUTHORIZED)

        access_token, new_refresh_token = tokens

        return Response({
            'access_token': access_token,
            'refresh_token': new_refresh_token,
            'expires_in': 3600  # 1 hour in seconds
        })

    except Exception as e:
        logger.error(f"Error refreshing lab token: {str(e)}")
        return Response({
            'error': 'Failed to refresh token'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([AllowAny])
def verify_lab_token_view(request):
    """
    Verify a token for lab environment access.
    This endpoint is used by the lab environment to verify tokens.
    """
    try:
        token = request.data.get('token')
        if not token:
            return Response(
                {'error': 'Token is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Verify the token
        payload = token_manager.verify_token(token)
        if not payload:
            return Response(
                {'error': 'Invalid token'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Check if token is for lab access
        if payload.get('token_type') != 'lab':
            return Response(
                {'error': 'Invalid token type'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Return minimal required user data
        user_data = {
            'user_id': payload.get('user_id'),
            'username': payload.get('username'),
            'email': payload.get('email'),
            'role': payload.get('role'),
            'lab_id': payload.get('lab_id'),
            'token_type': payload.get('token_type'),
            'exp': payload.get('exp')
        }

        # Log successful verification
        logger.info(f"Token verified successfully for user {user_data['username']}")

        return Response(user_data)

    except Exception as e:
        logger.error(f"Token verification failed: {str(e)}")
        return Response(
            {'error': 'Token verification failed'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        ) 