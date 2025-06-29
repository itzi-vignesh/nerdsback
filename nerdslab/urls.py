from django.contrib import admin
from django.urls import path, include
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.http import HttpResponse
from django.conf import settings
from django.conf.urls.static import static
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)
from . import views

@api_view(['GET'])
@permission_classes([AllowAny])
def api_health_check(request):
    return Response({'status': 'healthy'})

# Simple test view to check if basic routing works
def test_view(request):
    return HttpResponse("Server is working correctly in HTTP mode!")

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),
    
    # JWT Token endpoints - CRITICAL for token-based authentication
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    
    # Health and test endpoints
    path('health/', views.health_check, name='health_check'),
    path('test/', views.ratelimit_view, name='ratelimit_view'),
    
    # Authentication and data endpoints
    path('auth/decrypt/', views.decrypt_frontend_data, name='decrypt_frontend_data'),
    
    # Lab token management endpoints
    path('labs/token/generate/', views.generate_lab_token_view, name='generate_lab_token'),
    path('labs/token/refresh/', views.refresh_lab_token_view, name='refresh_lab_token'),
    path('labs/token/verify/', views.verify_lab_token_view, name='verify_lab_token'),
    
    # Lab management endpoints
    path('api/verify-lab-access/', views.verify_lab_access, name='verify_lab_access'),
    path('labs/templates/', views.get_lab_templates, name='lab_templates'),
    path('labs/status/', views.get_lab_status, name='lab_status'),
    path('labs/verify-flag/', views.verify_flag, name='verify_flag'),
    
    # API test endpoint
    path('api/test/', views.api_test_endpoint, name='api_test'),
]

# Serve static and media files in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)