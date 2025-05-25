from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import LabFlag, LabSubmission
from accounts.models import UserLab, UserLabProgress
from django.shortcuts import get_object_or_404
from django.utils import timezone
import requests
from django.conf import settings
import psutil
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods
from django.core.cache import cache
from django_ratelimit.decorators import ratelimit

def handle_options_request(request):
    response = HttpResponse()
    response['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
    response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
    response['Access-Control-Allow-Headers'] = 'X-Requested-With, Content-Type, Authorization, X-User-Hash, X-CSRFToken'
    response['Access-Control-Allow-Credentials'] = 'true'
    response['Access-Control-Max-Age'] = '1728000'
    response['Access-Control-Expose-Headers'] = 'Content-Type, X-CSRFToken'
    return response

@api_view(['POST', 'OPTIONS'])
@permission_classes([IsAuthenticated])
def verify_flag(request):
    if request.method == 'OPTIONS':
        return handle_options_request(request)
        
    lab_id = request.data.get('lab_id')
    submitted_flag = request.data.get('flag')

    if not lab_id or not submitted_flag:
        return Response({
            'error': 'Missing lab_id or flag'
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Strip '-lab' suffix if present
        lab_id = lab_id.replace('-lab', '')
        lab = LabFlag.objects.get(lab_id=lab_id, is_active=True)
        
        # Check if user has already submitted this lab
        submission, created = LabSubmission.objects.get_or_create(
            user=request.user,
            lab=lab,
            defaults={'submitted_flag': submitted_flag}
        )

        if not created:
            submission.submitted_flag = submitted_flag
            submission.save()

        # Verify the flag
        is_correct = submitted_flag.strip() == lab.flag_value.strip()
        submission.is_correct = is_correct
        submission.save()

        # If flag is correct, mark the lab as completed
        if is_correct:
            try:
                user_lab = UserLab.objects.get(
                    user=request.user,
                    lab_id=f"{lab_id}-lab"
                )
                user_lab.status = 'completed'
                user_lab.completed_at = timezone.now()
                user_lab.save()

                # Create or update progress
                UserLabProgress.objects.update_or_create(
                    user_lab=user_lab,
                    step='flag_submission',
                    defaults={
                        'is_completed': True,
                        'notes': 'Flag successfully verified'
                    }
                )
            except UserLab.DoesNotExist:
                # If UserLab doesn't exist, create it
                user_lab = UserLab.objects.create(
                    user=request.user,
                    lab_id=f"{lab_id}-lab",
                    lab_type=lab_id,
                    lab_url=f"https://labs.nerdslab.in/{lab_id}",
                    status='completed',
                    completed_at=timezone.now()
                )
                UserLabProgress.objects.create(
                    user_lab=user_lab,
                    step='flag_submission',
                    is_completed=True,
                    notes='Flag successfully verified'
                )

        return Response({
            'is_correct': is_correct,
            'message': 'Flag verified successfully' if is_correct else 'Incorrect flag',
            'lab_completed': is_correct
        })

    except LabFlag.DoesNotExist:
        return Response({
            'error': 'Lab not found'
        }, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET', 'OPTIONS'])
@permission_classes([IsAuthenticated])
def get_lab_status(request):
    if request.method == 'OPTIONS':
        return handle_options_request(request)
    user = request.user
    submissions = LabSubmission.objects.filter(user=user)
    
    status_data = []
    for submission in submissions:
        status_data.append({
            'lab_id': f"{submission.lab.lab_id}-lab",
            'lab_name': submission.lab.get_lab_id_display(),
            'is_completed': submission.is_correct,
            'submitted_at': submission.submitted_at
        })
    
    return Response(status_data)

@api_view(['POST', 'OPTIONS'])
@permission_classes([IsAuthenticated])
def start_lab_session(request):
    if request.method == 'OPTIONS':
        return handle_options_request(request)
        
    lab_id = request.data.get('lab_id')
    user_hash = request.data.get('user_hash')

    if not lab_id or not user_hash:
        return Response({
            'error': 'Missing lab_id or user_hash'
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Map lab IDs to the format expected by lab.nerdslab.in
        lab_id_mapping = {
            'mediconnect-lab': 'lab1',
            'feedme-lab': 'lab2'
        }
        
        mapped_lab_id = lab_id_mapping.get(lab_id)
        if not mapped_lab_id:
            return Response({
                'error': 'Invalid lab ID'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Send request to lab.nerdslab.in
        response = requests.post(
            'https://lab.nerdslab.in/api/start-lab/',
            json={
                'lab_id': mapped_lab_id,
                'user_hash': user_hash
            },
            headers={'Content-Type': 'application/json'}
        )

        if response.status_code == 200:
            return Response(response.json())
        elif response.status_code == 400:
            return Response({
                'error': 'Lab session already exists for this user'
            }, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({
                'error': 'Failed to start lab session'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except requests.RequestException as e:
        return Response({
            'error': f'Failed to start lab session: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST', 'OPTIONS'])
@permission_classes([IsAuthenticated])
def stop_lab_session(request):
    if request.method == 'OPTIONS':
        return handle_options_request(request)
        
    lab_id = request.data.get('lab_id')
    user_hash = request.data.get('user_hash')

    if not lab_id or not user_hash:
        return Response({
            'error': 'Missing lab_id or user_hash'
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Map lab IDs to the format expected by lab.nerdslab.in
        lab_id_mapping = {
            'mediconnect-lab': 'lab1',
            'feedme-lab': 'lab2'
        }
        
        mapped_lab_id = lab_id_mapping.get(lab_id)
        if not mapped_lab_id:
            return Response({
                'error': 'Invalid lab ID'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Send request to lab.nerdslab.in
        response = requests.post(
            'https://lab.nerdslab.in/api/stop-lab/',
            json={
                'lab_id': mapped_lab_id,
                'user_hash': user_hash
            },
            headers={'Content-Type': 'application/json'}
        )

        if response.status_code == 200:
            return Response(response.json())
        elif response.status_code == 404:
            return Response({
                'error': 'Lab session not found'
            }, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({
                'error': 'Failed to stop lab session'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except requests.RequestException as e:
        return Response({
            'error': f'Failed to stop lab session: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET', 'OPTIONS'])
@permission_classes([IsAuthenticated])
def get_lab_details(request, lab_id):
    if request.method == 'OPTIONS':
        return handle_options_request(request)
    try:
        # Get lab details from LabFlag model
        lab = LabFlag.objects.get(lab_id=lab_id.replace('-lab', ''), is_active=True)
        
        # Get user's submission if exists
        submission = LabSubmission.objects.filter(
            user=request.user,
            lab=lab
        ).first()
        
        # Get user's lab instance if exists
        user_lab = UserLab.objects.filter(
            user=request.user,
            lab_id=lab_id
        ).first()
        
        # Map lab details to frontend expected format
        lab_details = {
            'id': lab.lab_id,
            'title': lab.get_lab_id_display(),
            'description': f"This is a {lab.get_lab_id_display()} lab. Your goal is to find and submit the correct flag. Look for clues in the application to determine the flag format.",
            'difficulty': 'intermediate',  # Default difficulty
            'category': 'Web Security',    # Default category
            'estimated_minutes': 30,       # Default time
            'points_awarded': 100,         # Default points
            'lab_type': lab.lab_id,
            'docker_image': f"nerdslab/{lab.lab_id}:latest",
            'status': user_lab.status if user_lab else 'stopped',
            'created_at': user_lab.created_at if user_lab else None,
            'url': user_lab.lab_url if user_lab else None,
            'is_completed': submission.is_correct if submission else False
        }
        
        return Response(lab_details)
    except LabFlag.DoesNotExist:
        return Response({
            'error': 'Lab not found'
        }, status=status.HTTP_404_NOT_FOUND)

@require_http_methods(["GET"])
def health_check(request):
    """Health check endpoint for monitoring."""
    try:
        # Check disk usage
        disk_usage = psutil.disk_usage('/')
        if disk_usage.percent > settings.HEALTH_CHECK['DISK_USAGE_MAX']:
            return JsonResponse({
                'status': 'error',
                'message': 'Disk usage too high',
                'disk_usage': disk_usage.percent
            }, status=500)

        # Check memory usage
        memory = psutil.virtual_memory()
        if memory.available < settings.HEALTH_CHECK['MEMORY_MIN'] * 1024 * 1024:  # Convert MB to bytes
            return JsonResponse({
                'status': 'error',
                'message': 'Memory usage too high',
                'memory_available': memory.available
            }, status=500)

        # Check database connection
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()

        # Check Redis connection
        cache.set('health_check', 'ok', 1)
        if cache.get('health_check') != 'ok':
            return JsonResponse({
                'status': 'error',
                'message': 'Redis connection failed'
            }, status=500)

        return JsonResponse({
            'status': 'healthy',
            'disk_usage': disk_usage.percent,
            'memory_available': memory.available,
            'database': 'connected',
            'redis': 'connected'
        })

    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@ratelimit(key='ip', rate='100/h', block=True)
@require_http_methods(["GET"])
def ratelimit_view(request):
    """View for rate limit exceeded."""
    return JsonResponse({
        'status': 'error',
        'message': 'Rate limit exceeded. Please try again later.'
    }, status=429) 