from __future__ import annotations

import logging
import os
import time
import traceback
import uuid
import hashlib
from datetime import timedelta
from smtplib import SMTPAuthenticationError, SMTPConnectError, SMTPException
from socket import timeout as SocketTimeout
from typing import Any, Dict

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.core.cache import cache
from django.core.mail import EmailMultiAlternatives, get_connection
from django.http import HttpResponse, JsonResponse
from django.middleware.csrf import get_token
from django.shortcuts import get_object_or_404, render
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.html import strip_tags
from django.views.decorators.csrf import csrf_exempt
from rest_framework import generics, permissions, serializers, status
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from nerdslab.email_config import (  # noqa: E501 – local project import
    send_password_reset_email,
    send_verification_email,
)

from .models import EmailVerificationToken, PasswordResetToken, UserProfile
from .serializers import (  # noqa: E501 – keep grouped
    EmailVerificationSerializer,
    LoginSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    RegisterSerializer,
    UserSerializer,
)

logger = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────────────────
#  Token Management Functions
# ────────────────────────────────────────────────────────────────────────────────

def generate_jti():
    """Generate a unique JWT ID for token identification."""
    return str(uuid.uuid4())

def generate_token_fingerprint(user):
    """Generate a unique fingerprint for token security."""
    base_string = f"{user.id}:{user.username}:{user.email}:{timezone.now().timestamp()}"
    return hashlib.sha256(base_string.encode()).hexdigest()

def store_fingerprint(user_id, fingerprint):
    """Store user fingerprint in cache for token validation."""
    cache_key = f'user_fingerprint_{user_id}'
    cache.set(cache_key, fingerprint, timeout=settings.TOKEN_SETTINGS['ACCESS_TOKEN_LIFETIME'].total_seconds())

def revoke_token(jti):
    """Revoke a token by adding its JTI to blacklist."""
    cache_key = f'revoked_token_{jti}'
    # Set with long expiration to ensure token stays blacklisted
    cache.set(cache_key, True, timeout=settings.TOKEN_SETTINGS['REFRESH_TOKEN_LIFETIME'].total_seconds())

def is_token_revoked(jti):
    """Check if a token is revoked."""
    cache_key = f'revoked_token_{jti}'
    return cache.get(cache_key, False)

def validate_token_fingerprint(user_id, fingerprint):
    """Validate token fingerprint against stored value."""
    cache_key = f'user_fingerprint_{user_id}'
    stored_fingerprint = cache.get(cache_key)
    return stored_fingerprint == fingerprint if stored_fingerprint else False


# ────────────────────────────────────────────────────────────────────────────────
#  Auth / Register / Login Views
# ────────────────────────────────────────────────────────────────────────────────


@method_decorator(csrf_exempt, name="dispatch")
class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes: list[Any] = []
    serializer_class = RegisterSerializer
    
    def post(self, request, *args, **kwargs):  # noqa: D401 – keep signature
        """Handle user registration with atomic transaction and token return."""
        serializer = RegisterSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            from django.db import transaction

            with transaction.atomic():
                user = serializer.save()
                token, _ = Token.objects.get_or_create(user=user)
            
            return Response(
                {
                "message": "Registration successful.",
                "user": UserSerializer(user).data,
                    "token": token.key,
                },
                status=status.HTTP_201_CREATED,
            )
        except serializers.ValidationError as exc:
            errors = exc.detail
            if "password" in errors:
                errors["password"] = self._friendly_password_errors(errors["password"])
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)
    
    @staticmethod
    def _friendly_password_errors(password_errors):  # type: ignore[override]
        msgs: list[str] = []
        mapping = {
            "similar to": "Your password is too similar to your personal information.",
            "too common": "Please choose a stronger password.",
            "entirely numeric": "Include letters or special characters.",
            "too short": "Password must be at least 8 characters.",
        }
        for err in password_errors:
            err_str = str(err)
            for key, friendly in mapping.items():
                if key in err_str:
                    msgs.append(friendly)
                    break
            else:
                msgs.append(err_str)
        return msgs


@method_decorator(csrf_exempt, name="dispatch")
class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes: list[Any] = []
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        username = serializer.validated_data["username"]
        password = serializer.validated_data["password"]
        user = authenticate(username=username, password=password)
        if not user:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        # Add custom claims
        refresh['token_type'] = 'refresh'
        refresh['token_version'] = settings.JWT_TOKEN_VERSION
        refresh['jti'] = generate_jti()

        access['token_type'] = 'access'
        access['token_version'] = settings.JWT_TOKEN_VERSION
        access['jti'] = generate_jti()

        # Store fingerprint
        fingerprint = generate_token_fingerprint(user)
        store_fingerprint(user.id, fingerprint)
        refresh['fingerprint'] = fingerprint
        access['fingerprint'] = fingerprint

        return Response({
            "access": str(access),
            "refresh": str(refresh),
            "user": UserSerializer(user).data
        })


@method_decorator(csrf_exempt, name="dispatch")
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication, SessionAuthentication]
    
    def post(self, request, *args, **kwargs):
        try:
            # Get the refresh token from the request
            refresh_token = request.data.get("refresh")
            if refresh_token:
                # Blacklist the refresh token
                token = RefreshToken(refresh_token)
                token.blacklist()
                
                # Also blacklist the access token if available
                if 'jti' in token.payload:
                    revoke_token(token.payload['jti'])
                
                # Clear user fingerprint
                if request.user.id:
                    cache_key = f'user_fingerprint_{request.user.id}'
                    cache.delete(cache_key)
            
            # Clear session
            logout(request)
            
            return Response({
                "status": "success",
                "message": "Successfully logged out"
            })
        except Exception as e:
            logger.warning(f"Logout error: {str(e)}", exc_info=True)
            return Response({
                "status": "error",
                "message": "Error during logout"
            }, status=status.HTTP_400_BAD_REQUEST)


class UserDetailView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):  # noqa: D401 – DRF override
        return self.request.user

@method_decorator(csrf_exempt, name="dispatch")
class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    @method_decorator(csrf_exempt)  # method‑only decorator
    def post(self, request, *args, **kwargs):  # noqa: D401 – keep signature
        serializer = PasswordResetRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        email = serializer.validated_data["email"]
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Don't leak user existence.
            return Response(
                {"detail": "If an account exists with this email, you will receive a password reset link."},
                status=status.HTTP_200_OK,
            )

        token = PasswordResetToken.objects.create(
            user=user,
            expires_at=timezone.now() + timedelta(hours=24),
        )
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token.token}"

        # Prepare and send the mail (retry loop preserved, indentation fixed)
        context: Dict[str, Any] = {"user": user, "reset_url": reset_url, "expiry_hours": 24}
        html = render_to_string("emails/password_reset.html", context)
        text = strip_tags(html)
        msg = EmailMultiAlternatives(
            "Reset Your NerdsLab Password",
            text,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
        )
        msg.attach_alternative(html, "text/html")
            
        last_err: Exception | None = None
        for attempt in range(1, settings.SMTP_MAX_RETRIES + 1):
            try:
                msg.send()
                break
            except (SMTPAuthenticationError, SMTPConnectError, SMTPException, SocketTimeout) as exc:
                last_err = exc
                logger.warning("Email send failed (%s/%s): %s", attempt, settings.SMTP_MAX_RETRIES, exc)
                time.sleep(settings.SMTP_RETRY_DELAY)
        else:
            token.delete()
            return Response(
                {"detail": "Failed to send password reset email. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {"detail": "If an account exists with this email, you will receive a password reset link."},
            status=status.HTTP_200_OK,
        )


class PasswordResetConfirmView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []  # No authentication required for password reset confirmation
    
    def post(self, request):
        # Debug request information
        print("Password reset confirm headers:", request.headers)
        print("Password reset confirm path:", request.path)
        
        token = request.data.get('token')
        password = request.data.get('password')
        password2 = request.data.get('password2')
        
        if not token:
            return Response(
                {'error': 'Token is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if not password:
            return Response(
                {'password': ['This field is required']},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if not password2:
            return Response(
                {'password2': ['This field is required']},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if password != password2:
            return Response(
                {'password': ['Password fields didn\'t match']},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            reset_token = PasswordResetToken.objects.get(token=token)
            
            if not reset_token.is_valid():
                return Response(
                    {'error': 'Token is invalid or expired'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate password using Django's validators
            user = reset_token.user
            try:
                # Use the same validation as in the serializer
                from django.contrib.auth.password_validation import validate_password
                validate_password(password, user)
                
                # Reset password
                user.set_password(password)
                user.save()
                
                # Mark token as used
                reset_token.is_used = True
                reset_token.save()
                
                return Response({'message': 'Password reset successful'})
            except Exception as validation_error:
                # Handle password validation errors with more specific messages
                error_messages = []
                for error in validation_error:
                    error_str = str(error)
                    
                    if "similar to" in error_str:
                        error_messages.append("Your password is too similar to your personal information. Please choose a more unique password.")
                    elif "too common" in error_str or "commonly used password" in error_str:
                        error_messages.append("The password you chose is too common. Please choose a stronger password.")
                    elif "entirely numeric" in error_str:
                        error_messages.append("Your password cannot consist of only numbers. Please include letters or special characters.")
                    elif "too short" in error_str:
                        error_messages.append("Your password is too short. It must contain at least 8 characters.")
                    elif "keyboard pattern" in error_str or "common pattern" in error_str or "predictable pattern" in error_str:
                        error_messages.append("Your password uses a common guessable pattern. Please use a more unique combination.")
                    elif "common word" in error_str:
                        error_messages.append("Your password contains a common word that makes it easily guessable. Please choose a stronger password.")
                    elif "l33t speak" in error_str or "leet_pattern" in error_str or "leet_word" in error_str:
                        error_messages.append("Your password uses common letter-to-symbol substitutions (like '@' for 'a'). Please use a more unique combination.")
                    elif "alternating case" in error_str:
                        error_messages.append("Your password uses an alternating case pattern (like 'QwErTy'). Please use a more unique combination.")
                    else:
                        error_messages.append(error_str)
                
                return Response(
                    {'password': error_messages},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        except PasswordResetToken.DoesNotExist:
            return Response(
                {'error': 'Invalid token'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        # Debug authentication info
        print("Auth header:", request.META.get('HTTP_AUTHORIZATION'))
        print("User authenticated:", request.user.is_authenticated)
        print("User:", request.user)
        
        user = request.user
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')
        
        # Validate input
        if not current_password or not new_password:
            return Response(
                {'error': 'Both current and new password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Verify current password
        if not user.check_password(current_password):
            return Response(
                {'current_password': ['The current password is incorrect']},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Validate new password using Django's validators
        try:
            from django.contrib.auth.password_validation import validate_password
            validate_password(new_password, user)
            
            # Set new password
            user.set_password(new_password)
            user.save()
            
            # Generate new token (since password change invalidates sessions)
            token, _ = Token.objects.get_or_create(user=user)
            
            return Response({
                'message': 'Password changed successfully',
                'token': token.key
            })
        except Exception as validation_error:
            # Handle password validation errors with more specific messages
            error_messages = []
            for error in validation_error:
                error_str = str(error)
                
                if "similar to" in error_str:
                    error_messages.append("Your password is too similar to your personal information. Please choose a more unique password.")
                elif "too common" in error_str or "commonly used password" in error_str:
                    error_messages.append("The password you chose is too common. Please choose a stronger password.")
                elif "entirely numeric" in error_str:
                    error_messages.append("Your password cannot consist of only numbers. Please include letters or special characters.")
                elif "too short" in error_str:
                    error_messages.append("Your password is too short. It must contain at least 8 characters.")
                elif "keyboard pattern" in error_str or "common pattern" in error_str or "predictable pattern" in error_str:
                    error_messages.append("Your password uses a common guessable pattern. Please use a more unique combination.")
                elif "common word" in error_str:
                    error_messages.append("Your password contains a common word that makes it easily guessable. Please choose a stronger password.")
                elif "l33t speak" in error_str or "leet_pattern" in error_str or "leet_word" in error_str:
                    error_messages.append("Your password uses common letter-to-symbol substitutions (like '@' for 'a'). Please use a more unique combination.")
                elif "alternating case" in error_str:
                    error_messages.append("Your password uses an alternating case pattern (like 'QwErTy'). Please use a more unique combination.")
                else:
                    error_messages.append(error_str)
            
            return Response(
                {'new_password': error_messages},
                status=status.HTTP_400_BAD_REQUEST
            )


class EmailVerificationView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []
    
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        token_str = str(serializer.validated_data['token'])
        
        # Check cache first
        cache_key = f'email_verification_{token_str}'
        cached_result = cache.get(cache_key)
        
        if cached_result and not cached_result.get('is_valid'):
            return Response(
                {'error': 'Verification link is invalid or has expired'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Use select_related to get user in a single query
            token = EmailVerificationToken.objects.select_related('user').get(token=token_str)
            
            if not token.is_valid():
                # Cache invalid token result
                cache.set(cache_key, {'is_valid': False}, timeout=48*3600)
                return Response(
                    {'error': 'Verification link is invalid or has expired'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Use transaction to ensure atomicity
            from django.db import transaction
            with transaction.atomic():
                user = token.user
                user.is_active = True
                user.save()
                
                # Mark token as used
                token.is_used = True
                token.save()
                
                # Generate authentication token for the user
                auth_token, _ = Token.objects.get_or_create(user=user)
            
            # Cache the verification result
            cache.delete(cache_key)
            
            return Response({
                'message': 'Email verified successfully. Your account is now active.',
                'token': auth_token.key,
                'user': UserSerializer(user).data
            })
            
        except EmailVerificationToken.DoesNotExist:
            # Cache negative result
            cache.set(cache_key, {'is_valid': False}, timeout=48*3600)
            return Response(
                {'error': 'Invalid verification token'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def get(self, request):
        token = request.query_params.get('token')
        if not token:
            return Response(
                {'error': 'Token is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check cache first
        cache_key = f'email_verification_{token}'
        cached_result = cache.get(cache_key)
        
        if cached_result is not None:
            return Response(
                {'is_valid': cached_result.get('is_valid', False)},
                status=status.HTTP_200_OK
            )
        
        try:
            token_obj = EmailVerificationToken.objects.get(token=token)
            is_valid = token_obj.is_valid()
            
            # Cache the result
            cache.set(cache_key, {'is_valid': is_valid}, timeout=48*3600)
            
            if not is_valid:
                return Response(
                    {'is_valid': False, 'error': 'Verification link is invalid or has expired'},
                    status=status.HTTP_200_OK
                )
            
            return Response(
                {'is_valid': True},
                status=status.HTTP_200_OK
            )
            
        except EmailVerificationToken.DoesNotExist:
            # Cache negative result
            cache.set(cache_key, {'is_valid': False}, timeout=48*3600)
            return Response(
                {'is_valid': False, 'error': 'Invalid verification token'},
                status=status.HTTP_200_OK
            )


class ResendVerificationEmailView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []  # No authentication required for resending verification
    
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response(
                {'error': 'Email is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            user = User.objects.get(email=email, is_active=False)
            
            # Create a new verification token
            old_tokens = EmailVerificationToken.objects.filter(user=user, is_used=False)
            for token in old_tokens:
                token.is_used = True
                token.save()
                
            token = EmailVerificationToken.objects.create(user=user)
            
            # Prepare email with template
            verify_url = f"{settings.FRONTEND_URL}/verify-email?token={token.token}"
            context = {
                'verify_url': verify_url,
                'user': user,
                'expiry_hours': 48,  # Token expiry in hours
            }
            
            # Render HTML email template
            html_content = render_to_string('emails/email_verification.html', context)
            text_content = strip_tags(html_content)  # Generate plain text version
            
            # Create email with timeout settings
            subject = 'Verify Your NerdsLab Account'
            from_email = settings.DEFAULT_FROM_EMAIL
            to = [user.email]
            
            msg = EmailMultiAlternatives(
                subject, 
                text_content, 
                from_email, 
                to,
                connection=get_connection(timeout=settings.EMAIL_TIMEOUT)
            )
            msg.attach_alternative(html_content, "text/html")
            
            # Implement retry mechanism
            from smtplib import SMTPException
            from socket import timeout as SocketTimeout
            import time
            import logging
            
            logger = logging.getLogger('accounts')
            
            for attempt in range(settings.SMTP_MAX_RETRIES):
                try:
                    msg.send()
                    logger.info(f"Resent verification email successfully to {user.email}")
                    return Response({'message': 'Verification email sent'})
                except (SMTPException, SocketTimeout) as e:
                    if attempt < settings.SMTP_MAX_RETRIES - 1:
                        logger.warning(f"Resend verification email failed (attempt {attempt + 1}): {str(e)}")
                        time.sleep(settings.SMTP_RETRY_DELAY)
                    else:
                        logger.error(f"All resend verification email attempts failed for {user.email}: {str(e)}")
                        return Response(
                            {'error': 'Failed to send verification email. Please try again later.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR
                        )
                except Exception as e:
                    logger.error(f"Unexpected error resending verification email to {user.email}: {str(e)}")
                    return Response(
                        {'error': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
            
        except User.DoesNotExist:
            # Don't reveal if email exists for security reasons
            return Response({'message': 'If the email exists and is unverified, a verification email has been sent'})
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


def csrf_failure(request, reason=""):
    """View for CSRF failure errors"""
    if request.headers.get('content-type') == 'application/json':
        return JsonResponse({
            'error': 'CSRF validation failed. Refresh the page and try again.',
            'details': reason
        }, status=403)
    
    # For HTML requests
    return render(request, 'accounts/csrf_error.html', {'reason': reason}, status=403)


@method_decorator(csrf_exempt, name='dispatch')
class GetCSRFTokenView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []
    
    def get(self, request):
        """Get a new CSRF token."""
        try:
            # Get a new CSRF token
            csrf_token = get_token(request)
            
            # Set the CSRF cookie
            response = Response({
                'status': 'success',
                'message': 'CSRF token generated successfully'
            })
            response.set_cookie(
                'csrftoken',
                csrf_token,
                samesite='Lax',
                secure=settings.CSRF_COOKIE_SECURE,
                httponly=False  # Must be accessible to JavaScript
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Error generating CSRF token: {str(e)}")
            return Response({
                'status': 'error',
                'message': 'Failed to generate CSRF token'
            }, status=500)