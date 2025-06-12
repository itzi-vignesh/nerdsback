from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from .models import LabFlag, LabSubmission
from accounts.models import UserLab, UserLabProgress
from django.shortcuts import get_object_or_404
from django.utils import timezone
import requests
from django.conf import settings
import psutil
from django.http import JsonResponse, HttpResponse
from django.core.cache import cache
from django_ratelimit.decorators import ratelimit
import json
from .utils import generate_lab_token, verify_lab_token, extract_user_info
import logging

logger = logging.getLogger(__name__)

# Lab templates data
LAB_TEMPLATES = [
    {
        "id": "mediconnect-lab",
        "track_id": "track-1",
        "module_id": "module-1",
        "title": "MediConnect Web Application Security",
        "description": "Practice web security testing on a medical records management system. Learn to identify and exploit vulnerabilities in a healthcare application while understanding the importance of securing sensitive medical data.",
        "difficulty": "medium",
        "category": "Web Security",
        "estimated_minutes": 90,
        "points_awarded": 250,
        "lab_type": "docker",
        "docker_image": "mediconnect_app"
    },
    {
        "id": "feedme-lab",
        "track_id": "track-1",
        "module_id": "module-1",
        "title": "FeedMe Social Media Security",
        "description": "Explore social media application security by testing a vulnerable social networking platform. Practice identifying and exploiting common web vulnerabilities in a realistic environment.",
        "difficulty": "medium",
        "category": "Web Security",
        "estimated_minutes": 75,
        "points_awarded": 200,
        "lab_type": "docker",
        "docker_image": "feedme_app"
    }
]

@csrf_exempt
@require_http_methods(["POST"])
@api_view(['POST'])
@permission_classes([AllowAny])
def login_handler(request):
    """
    Custom login handler that supports both token and session authentication
    """
    username = request.data.get('username')
    password = request.data.get('password')
    
    if not username or not password:
        return Response({
            'error': 'Username and password are required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Authenticate user
    user = authenticate(username=username, password=password)
    
    if user is None:
        return Response({
            'error': 'Invalid credentials'
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    if not user.is_active:
        return Response({
            'error': 'User account is disabled'
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    # Generate or get existing token
    token, _ = Token.objects.get_or_create(user=user)
    
    # Get user data
    user_data = {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'is_staff': user.is_staff,
        'is_superuser': user.is_superuser
    }
    
    return Response({
        'token': token.key,
        'user': user_data
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_flag(request):
    """
    Verify a flag submission for a lab
    """
    lab_id = request.data.get('lab_id')
    flag = request.data.get('flag')
    
    if not lab_id or not flag:
        return Response(
            {'error': 'Lab ID and flag are required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # TODO: Implement actual flag verification
    return Response({
        'status': 'success',
        'message': 'Flag verified successfully',
        'is_correct': True
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_lab_templates(request):
    """
    Get available lab templates
    """
    return Response(LAB_TEMPLATES)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_lab_status(request):
    """
    Get status of all labs for the current user
    """
    # TODO: Implement actual lab status checking
    return Response([])

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def start_lab_session(request):
    """
    Start a new lab session
    """
    lab_id = request.data.get('lab_id')
    user_hash = request.data.get('user_hash')

    if not lab_id or not user_hash:
        return Response(
            {'error': 'Lab ID and user hash are required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # TODO: Implement actual lab session creation
    return Response({
        'status': 'success',
        'message': 'Lab session started',
        'url': f'https://lab-{lab_id}.nerdslab.in'
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def stop_lab_session(request):
    """
    Stop a running lab session
    """
    lab_id = request.data.get('lab_id')
    user_hash = request.data.get('user_hash')

    if not lab_id or not user_hash:
        return Response(
            {'error': 'Lab ID and user hash are required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # TODO: Implement actual lab session termination
    return Response({
        'status': 'success',
        'message': 'Lab session stopped'
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_lab_details(request, lab_id):
    """
    Get details for a specific lab
    """
    # Find lab template
    lab_template = next((lab for lab in LAB_TEMPLATES if lab['id'] == lab_id), None)
    
    if not lab_template:
        return Response(
            {'error': 'Lab not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    return Response(lab_template)

@require_http_methods(["GET"])
def health_check(request):
    return JsonResponse({'status': 'healthy'})

@ratelimit(key='ip', rate='100/h', block=True)
@require_http_methods(["GET"])
def ratelimit_view(request):
    return JsonResponse({'status': 'ok'})

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

        # Generate the token
        token = generate_lab_token(
            username=request.user.username,
            lab_id=lab_id,
            user_data=user_data
        )

        logger.info(f"Generated lab token for user {request.user.username} and lab {lab_id}")

        return Response({
            'token': token,
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