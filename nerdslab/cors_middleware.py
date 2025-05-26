from django.http import HttpResponse
from django.conf import settings

class CorsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Handle OPTIONS requests
        if request.method == "OPTIONS":
            response = HttpResponse()
            response.status_code = 200
        else:
            response = self.get_response(request)

        origin = request.headers.get('Origin')
        
        # In development mode, accept all origins
        if settings.DEBUG:
            if origin:
                response["Access-Control-Allow-Origin"] = origin
                response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
                response["Access-Control-Allow-Headers"] = (
                    "Accept, Accept-Encoding, Authorization, Content-Type, "
                    "DNT, Origin, User-Agent, X-CSRFToken, X-Requested-With, "
                    "X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, "
                    "Referrer-Policy, Content-Security-Policy, Strict-Transport-Security"
                )
                response["Access-Control-Allow-Credentials"] = "true"
                response["Access-Control-Max-Age"] = "86400"
        # In production mode, only allow specified origins
        elif origin in settings.CORS_ALLOWED_ORIGINS:
            response["Access-Control-Allow-Origin"] = origin
            response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
            response["Access-Control-Allow-Headers"] = (
                "Accept, Accept-Encoding, Authorization, Content-Type, "
                "DNT, Origin, User-Agent, X-CSRFToken, X-Requested-With, "
                "X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, "
                "Referrer-Policy, Content-Security-Policy, Strict-Transport-Security"
            )
            response["Access-Control-Allow-Credentials"] = "true"
            response["Access-Control-Max-Age"] = "86400"

        return response

class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Security headers
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["X-XSS-Protection"] = "1; mode=block"
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        
        # Allow all connections in development mode
        if settings.DEBUG:
            response["Content-Security-Policy"] = (
                "default-src 'self'; "
                "img-src 'self' data: https:; "
                "style-src 'self' 'unsafe-inline'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "connect-src 'self' http://localhost:8080 http://localhost:8000 *;"
            )
        else:
            response["Content-Security-Policy"] = (
                "default-src 'self'; "
                "img-src 'self' data: https:; "
                "style-src 'self' 'unsafe-inline'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "connect-src 'self' https://learn.nerdslab.in https://nerd-api.nerdslab.in https://lab.nerdslab.in;"
            )
        
        return response