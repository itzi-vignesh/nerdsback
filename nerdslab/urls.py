from django.contrib import admin
from django.urls import path, include
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.http import HttpResponse
from django.conf import settings
from django.conf.urls.static import static
from . import views

@api_view(['GET'])
@permission_classes([AllowAny])
def api_health_check(request):
    return Response({'status': 'healthy'})

def handle_options(request):
    response = HttpResponse()
    origin = request.headers.get('Origin')
    
    if origin in settings.CORS_ALLOWED_ORIGINS:
        response['Access-Control-Allow-Origin'] = origin
        response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
        response['Access-Control-Allow-Headers'] = 'Accept, Accept-Encoding, Authorization, Content-Type, Origin, X-CSRFToken, X-Requested-With'
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Max-Age'] = '86400'
    
    return response

# Simple test view to check if basic routing works
def test_view(request):
    return HttpResponse("Server is working correctly in HTTP mode!")

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),
    path('health/', api_health_check, name='health-check'),
    path('test/', test_view, name='test_view'),  # Add test URL
    path('labs/verify-flag/', views.verify_flag, name='verify_flag'),
    path('labs/status/', views.get_lab_status, name='lab_status'),
    path('labs/start/', views.start_lab_session, name='start_lab_session'),
    path('labs/stop/', views.stop_lab_session, name='stop_lab_session'),
    path('labs/details/<str:lab_id>/', views.get_lab_details, name='lab_details'),
    # Handle OPTIONS requests at the root level (should be last)
    path('', handle_options),
]

# Serve static and media files in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)