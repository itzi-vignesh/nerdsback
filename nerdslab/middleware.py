from django.utils.deprecation import MiddlewareMixin
import logging
from django.http import HttpResponse

logger = logging.getLogger(__name__)

class ApiCsrfExemptMiddleware(MiddlewareMixin):
    """
    Middleware to exempt API endpoints from CSRF protection
    """
    def process_view(self, request, view_func, view_args, view_kwargs):
        # Exempt API requests from CSRF
        if request.path.startswith('/api/') or request.path.startswith('/accounts/'):
            setattr(request, '_dont_enforce_csrf_checks', True)
        return None

class CorsHeadersMiddleware:
    """
    Middleware to add CORS headers to all responses to ensure proper cross-origin access
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method == 'OPTIONS':
            response = HttpResponse()
            response.status_code = 200
        else:
            response = self.get_response(request)

        # Add CORS headers to all responses
        origin = request.headers.get('Origin')
        allowed_origins = [
            'https://learn.nerdslab.in',
            'https://labs.nerdslab.in',
            'http://localhost:3000'
        ]
        
        if origin in allowed_origins:
            response["Access-Control-Allow-Origin"] = origin
            response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
            response["Access-Control-Allow-Headers"] = (
                "Accept, Accept-Encoding, Authorization, Content-Type, "
                "DNT, Origin, User-Agent, X-CSRFToken, X-Requested-With"
            )
            response["Access-Control-Allow-Credentials"] = "true"
            response["Access-Control-Max-Age"] = "86400"  # 24 hours

        return response

class CorsDebugMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Log CORS-related headers
        logger.info(f"Request method: {request.method}")
        logger.info(f"Request path: {request.path}")
        logger.info("Request headers:")
        for header, value in request.headers.items():
            logger.info(f"  {header}: {value}")

        response = self.get_response(request)

        # Log response headers
        logger.info("Response headers:")
        for header, value in response.headers.items():
            logger.info(f"  {header}: {value}")

        return response

class CloudflareProxyMiddleware:
    """
    Middleware to handle Cloudflare proxy headers and ensure proper CORS handling
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Handle Cloudflare headers
        if 'HTTP_CF_CONNECTING_IP' in request.META:
            request.META['REMOTE_ADDR'] = request.META['HTTP_CF_CONNECTING_IP']
        
        if 'HTTP_CF_VISITOR' in request.META:
            # Ensure proper scheme detection (http/https)
            try:
                import json
                cf_visitor = json.loads(request.META['HTTP_CF_VISITOR'])
                if cf_visitor.get('scheme') == 'https':
                    request.META['wsgi.url_scheme'] = 'https'
            except:
                pass

        response = self.get_response(request)
        
        # Ensure CORS headers are present
        if 'HTTP_ORIGIN' in request.META:
            origin = request.META['HTTP_ORIGIN']
            if origin in ['https://learn.nerdslab.in', 'https://labs.nerdslab.in']:
                response['Access-Control-Allow-Origin'] = origin
                response['Access-Control-Allow-Credentials'] = 'true'
                
                if request.method == 'OPTIONS':
                    response['Access-Control-Allow-Methods'] = 'DELETE, GET, OPTIONS, PATCH, POST, PUT'
                    response['Access-Control-Allow-Headers'] = 'accept, accept-encoding, authorization, content-type, dnt, origin, user-agent, x-csrftoken, x-requested-with'
                    response['Access-Control-Max-Age'] = '86400'
                    
        return response