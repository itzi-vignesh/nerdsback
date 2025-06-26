from __future__ import annotations

import logging
import time
import uuid
from datetime import timedelta
from smtplib import SMTPAuthenticationError, SMTPConnectError, SMTPException
from socket import timeout as SocketTimeout
from typing import Any, Dict

from django.conf import settings
from django.contrib.auth import authenticate, logout
from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.mail import EmailMultiAlternatives, get_connection
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.shortcuts import render
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.html import strip_tags
from django.views.decorators.csrf import csrf_exempt
from rest_framework import generics, permissions, serializers, status
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from nerdslab.frontend_crypto import FrontendCrypto

from .models import EmailVerificationToken, PasswordResetToken
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

        if not user.is_active:
            return Response({"error": "Account is inactive. Please verify your email."}, status=status.HTTP_401_UNAUTHORIZED)

        # Generate standard JWT tokens using Django REST Framework JWT
        try:
            from rest_framework_simplejwt.tokens import RefreshToken
            
            # Generate standard JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)
            
            # Generate traditional auth token for backward compatibility
            auth_token, _ = Token.objects.get_or_create(user=user)
            
            # Prepare data for encryption
            crypto = FrontendCrypto()
            sensitive_data = {
                "access": access_token,
                "refresh": refresh_token,
                "auth_token": auth_token.key,
                "user": UserSerializer(user).data
            }
            
            # Prepare user public data (also to be encrypted)
            user_public_data = {
                "id": user.id,
                "username": user.username,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "is_active": user.is_active,
                "is_verified": user.is_active,  # Use is_active as is_verified for now
                "is_staff": user.is_staff,
                "is_superuser": user.is_superuser,
                "date_joined": user.date_joined.isoformat() if user.date_joined else None,
                "last_login": user.last_login.isoformat() if user.last_login else None
            }
            
            # Encrypt both sensitive data and user public data for secure frontend storage
            encrypted_data = crypto.encrypt_token_data(sensitive_data)
            encrypted_user_public = crypto.encrypt_token_data(user_public_data)
            
            return Response({
                "encrypted_data": encrypted_data,
                "encrypted_user_public": encrypted_user_public,
                "session_key": crypto.generate_frontend_session_key(user.id, {
                    "session_id": request.session.session_key or "default",
                    "ip_address": request.META.get('REMOTE_ADDR', ''),
                    "user_agent": request.META.get('HTTP_USER_AGENT', '')
                })
            })
            
        except Exception as e:
            logger.error(f"Token generation failed: {str(e)}")
            return Response(
                {"error": "Authentication failed"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@method_decorator(csrf_exempt, name="dispatch")
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication, SessionAuthentication]
    
    def post(self, request, *args, **kwargs):
        try:
            # Get the refresh token from the request
            refresh_token = request.data.get("refresh")
            access_token = request.data.get("access")
            
            if refresh_token:
                # Revoke the refresh token using Django REST Framework JWT
                try:
                    from rest_framework_simplejwt.tokens import RefreshToken
                    from rest_framework_simplejwt.exceptions import InvalidToken
                    
                    # Decode the refresh token to get its JTI
                    refresh = RefreshToken(refresh_token)
                    jti = refresh.get('jti')
                    
                    if jti:
                        # Add to blacklist
                        from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
                        BlacklistedToken.objects.create(token__jti=jti)
                        logger.info(f"Successfully blacklisted refresh token with JTI: {jti}")
                except InvalidToken:
                    logger.warning("Invalid refresh token provided for logout")
                except Exception as e:
                    logger.warning(f"Failed to blacklist refresh token: {str(e)}")
            
            if access_token:
                # For access tokens, we can't blacklist them directly in DRF JWT
                # but we can log the logout for audit purposes
                try:
                    from rest_framework_simplejwt.tokens import AccessToken
                    access = AccessToken(access_token)
                    jti = access.get('jti')
                    logger.info(f"User logged out, access token JTI: {jti}")
                except Exception as e:
                    logger.warning(f"Failed to decode access token: {str(e)}")
                
            # Delete auth token
            try:
                request.user.auth_token.delete()
            except Exception:
                pass
            
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
        smtp_max_retries = getattr(settings, 'SMTP_MAX_RETRIES', 3)
        smtp_retry_delay = getattr(settings, 'SMTP_RETRY_DELAY', 2)
        
        for attempt in range(1, smtp_max_retries + 1):
            try:
                msg.send()
                break
            except (SMTPAuthenticationError, SMTPConnectError, SMTPException, SocketTimeout) as exc:
                last_err = exc
                logger.warning("Email send failed (%s/%s): %s", attempt, smtp_max_retries, exc)
                time.sleep(smtp_retry_delay)
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
    authentication_classes = []
    
    def post(self, request):
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
                # Handle password validation errors
                error_messages = []
                for error in validation_error:
                    error_str = str(error)
                    
                    if "similar to" in error_str:
                        error_messages.append("Your password is too similar to your personal information.")
                    elif "too common" in error_str:
                        error_messages.append("The password you chose is too common.")
                    elif "entirely numeric" in error_str:
                        error_messages.append("Your password cannot consist of only numbers.")
                    elif "too short" in error_str:
                        error_messages.append("Your password is too short. It must contain at least 12 characters.")
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
            # Handle password validation errors
            error_messages = []
            for error in validation_error:
                error_str = str(error)
                
                if "similar to" in error_str:
                    error_messages.append("Your password is too similar to your personal information.")
                elif "too common" in error_str:
                    error_messages.append("The password you chose is too common.")
                elif "entirely numeric" in error_str:
                    error_messages.append("Your password cannot consist of only numbers.")
                elif "too short" in error_str:
                    error_messages.append("Your password is too short. It must contain at least 12 characters.")
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


class ResendVerificationEmailView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []
    
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
                'expiry_hours': 48,
            }
            
            # Render HTML email template
            html_content = render_to_string('emails/email_verification.html', context)
            text_content = strip_tags(html_content)
            
            # Create email with timeout settings
            subject = 'Verify Your NerdsLab Account'
            from_email = settings.DEFAULT_FROM_EMAIL
            to = [user.email]
            
            msg = EmailMultiAlternatives(
                subject, 
                text_content, 
                from_email, 
                to,
                connection=get_connection(timeout=getattr(settings, 'EMAIL_TIMEOUT', 30))
            )
            msg.attach_alternative(html_content, "text/html")
            
            # Implement retry mechanism
            smtp_max_retries = getattr(settings, 'SMTP_MAX_RETRIES', 3)
            smtp_retry_delay = getattr(settings, 'SMTP_RETRY_DELAY', 2)
            
            for attempt in range(smtp_max_retries):
                try:
                    msg.send()
                    logger.info(f"Resent verification email successfully to {user.email}")
                    return Response({'message': 'Verification email sent'})
                except (SMTPException, SocketTimeout) as e:
                    if attempt < smtp_max_retries - 1:
                        logger.warning(f"Resend verification email failed (attempt {attempt + 1}): {str(e)}")
                        time.sleep(smtp_retry_delay)
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
                secure=getattr(settings, 'CSRF_COOKIE_SECURE', False),
                httponly=False  # Must be accessible to JavaScript
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Error generating CSRF token: {str(e)}")
            return Response({
                'status': 'error',
                'message': 'Failed to generate CSRF token'
            }, status=500)


@method_decorator(csrf_exempt, name="dispatch")
class DecryptUserDataView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication, SessionAuthentication]
    
    def post(self, request, *args, **kwargs):
        """
        Decrypt encrypted user data for frontend use.
        """
        try:
            encrypted_user_data = request.data.get('encrypted_user_data')
            if not encrypted_user_data:
                return Response(
                    {"error": "No encrypted user data provided"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Decrypt the user data
            crypto = FrontendCrypto()
            decrypted_data = crypto.decrypt_token_data(encrypted_user_data)
            
            if not decrypted_data:
                return Response(
                    {"error": "Failed to decrypt user data"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Verify the decrypted data belongs to the authenticated user
            if decrypted_data.get('id') != request.user.id:
                return Response(
                    {"error": "Unauthorized access to user data"}, 
                    status=status.HTTP_403_FORBIDDEN
                )
            
            return Response({
                "user_data": decrypted_data,
                "success": True
            })
            
        except Exception as e:
            logger.error(f"User data decryption failed: {str(e)}")
            return Response(
                {"error": "Decryption failed"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
