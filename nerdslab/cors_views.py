from django.http import HttpResponse
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

@csrf_exempt
@require_http_methods(["OPTIONS"])
@api_view(['OPTIONS'])
@permission_classes([AllowAny])
def cors_preflight(request):
    """
    Centralized CORS preflight handler that returns all necessary CORS headers.
    This endpoint should be called before making actual API requests to ensure
    proper CORS headers are set, even when behind Cloudflare.
    """
    response = HttpResponse()
    origin = request.headers.get('Origin')
    
    # List of allowed headers including security headers
    allowed_headers = [
        'Content-Type',
        'Authorization',
        'X-CSRFToken',
        'X-Requested-With',
        'X-User-Hash',
        'x-content-type-options',
        'x-frame-options',
        'x-xss-protection',
        'Accept',
        'Accept-Encoding',
        'Origin',
        'User-Agent'
    ]
    
    # List of exposed headers
    exposed_headers = [
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Content-Security-Policy',
        'Strict-Transport-Security'
    ]
    
    # Check if origin is allowed
    if settings.DEBUG or origin in settings.CORS_ALLOWED_ORIGINS:
        response['Access-Control-Allow-Origin'] = origin
        response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
        response['Access-Control-Allow-Headers'] = ', '.join(allowed_headers)
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Max-Age'] = '86400'  # 24 hours
        response['Access-Control-Expose-Headers'] = ', '.join(exposed_headers)
        
        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        
        # Set appropriate status code
        response.status_code = 200
    else:
        response.status_code = 403
    
    return response 