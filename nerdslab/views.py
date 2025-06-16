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
    """Custom login endpoint returning DRF token + basic user data."""

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

    token, _ = Token.objects.get_or_create(user=user)

    user_data = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "is_staff": user.is_staff,
        "is_superuser": user.is_superuser,
    }

    return Response({"token": token.key, "user": user_data})

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
#                          LAB SESSION (START / STOP)
# ---------------------------------------------------------------------------

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def start_lab_session(request):
    lab_id = request.data.get("lab_id")
    user_hash = request.data.get("user_hash")

    if not lab_id or not user_hash:
        return Response(
            {"error": "Lab ID and user hash are required"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # TODO: spin‑up logic here
    return Response(
        {
            "status": "success",
            "message": "Lab session started",
            "url": f"https://lab-{lab_id}.nerdslab.in",
        }
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def stop_lab_session(request):
    lab_id = request.data.get("lab_id")
    user_hash = request.data.get("user_hash")

    if not lab_id or not user_hash:
        return Response(
            {"error": "Lab ID and user hash are required"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # TODO: tear‑down logic here
    return Response({"status": "success", "message": "Lab session stopped"})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_lab_details(request, lab_id):
    lab_template = next((lab for lab in LAB_TEMPLATES if lab["id"] == lab_id), None)
    if lab_template is None:
        return Response({"error": "Lab not found"}, status=status.HTTP_404_NOT_FOUND)
    return Response(lab_template)

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

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def generate_lab_token_view(request):
    """Return short‑lived signed token so the lab VM can verify the user."""

    lab_id = request.data.get("lab_id")
    user_data = request.data.get("user_data", {})

    if not lab_id:
        return Response({"error": "Lab ID is required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        token = generate_lab_token(
            username=request.user.username,
            lab_id=lab_id,
            user_data=user_data,
        )
        logger.info("Generated lab token for %s – %s", request.user.username, lab_id)
        return Response({"token": token, "expires_in": 3600})

    except ValueError as exc:
        logger.error("Error generating lab token: %s", exc)
        return Response({"error": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except Exception as exc:  # noqa: BLE001 – catch‑all for now
        logger.error("Unexpected error generating lab token: %s", exc)
        return Response({"error": "Failed to generate lab token"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR) 