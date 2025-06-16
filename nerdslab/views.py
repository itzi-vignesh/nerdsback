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
    return Response(LAB_TEMPLATES)


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
        token = token_manager.generate_token_pair(
            user_id=request.user.id,
            username=request.user.username,
            email=request.user.email,
            role=request.user.role if hasattr(request.user, 'role') else None,
            token_type='lab',
            lab_id=request.data.get('lab_id')
        )
        
        return Response({
            'access_token': token['access_token'],
            'refresh_token': token['refresh_token']
        })
    except Exception as e:
        logger.error(f"Error generating lab token: {str(e)}")
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
            'valid': True,
            'user_id': payload['user_id'],
            'username': payload['username'],
            'lab_id': payload.get('lab_id')
        })
    except Exception as e:
        logger.error(f"Error verifying lab token: {str(e)}")
        return Response(
            {"error": "Failed to verify lab token"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        ) 