from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from django.core.mail import send_mail, EmailMultiAlternatives
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.middleware.csrf import get_token
import os
from rest_framework import serializers
from django.utils import timezone
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render

from .serializers import (
    UserSerializer,
    RegisterSerializer,
    LoginSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    EmailVerificationSerializer
)
from .models import UserProfile, PasswordResetToken, EmailVerificationToken
from nerdslab.email_config import send_verification_email, send_password_reset_email

@method_decorator(csrf_exempt, name='dispatch')
class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []
    serializer_class = RegisterSerializer
    
    def post(self, request, *args, **kwargs):
        # Log registration attempt
        print(f"Register request data: {request.data}")
        serializer = RegisterSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            
            # Use transaction.atomic to ensure data consistency
            from django.db import transaction
            with transaction.atomic():
                user = serializer.save()
                
                # Generate auth token for immediate login
                token, _ = Token.objects.get_or_create(user=user)
            
            return Response({
                "message": "Registration successful.",
                "user": UserSerializer(user).data,
                "token": token.key
            }, status=status.HTTP_201_CREATED)
            
        except serializers.ValidationError as e:
            errors = e.detail
            if 'password' in errors:
                errors['password'] = self.get_friendly_password_errors(errors['password'])
            # Log validation errors
            print(f"Specific validation errors: {errors}")
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get_friendly_password_errors(self, password_errors):
        friendly_messages = []
        for error in password_errors:
            error_str = str(error)
            if "similar to" in error_str:
                friendly_messages.append("Your password is too similar to your personal information")
            elif "too common" in error_str:
                friendly_messages.append("Please choose a stronger password")
            elif "entirely numeric" in error_str:
                friendly_messages.append("Include letters or special characters")
            elif "too short" in error_str:
                friendly_messages.append("Password must be at least 8 characters")
            else:
                friendly_messages.append(error_str)
        return friendly_messages

@method_decorator(csrf_exempt, name='dispatch')
class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []
    serializer_class = LoginSerializer
    
    def post(self, request, *args, **kwargs):
        # Log login attempt headers for debugging
        print(f"Login request headers: {dict(request.headers)}")
        
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            user = authenticate(username=username, password=password)
            
            if user:
                login(request, user)
                token, created = Token.objects.get_or_create(user=user)
                return Response({
                    "token": token.key,
                    "user": UserSerializer(user).data
                })
            return Response({
                "error": "Invalid credentials"
            }, status=status.HTTP_401_UNAUTHORIZED)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        # Delete token to logout
        try:
            request.user.auth_token.delete()
        except Exception:
            pass
        
        # Logout from session
        logout(request)
        
        return Response(
            {"message": "Successfully logged out"}, 
            status=status.HTTP_200_OK
        )

class UserDetailView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        return self.request.user

class PasswordResetRequestView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []  # No authentication required for password reset request
    
    def post(self, request):
        # Debug request information
        print("Password reset request headers:", request.headers)
        print("Password reset request path:", request.path)
        
        email = request.data.get('email')
        if not email:
            return Response(
                {'error': 'Email is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            user = User.objects.get(email=email)
            
            # Create token
            token = PasswordResetToken.objects.create(user=user)
            
            # Prepare email with template
            reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token.token}"
            context = {
                'reset_url': reset_url,
                'user': user,
            }
            
            # Render HTML email template
            html_content = render_to_string('emails/password_reset.html', context)
            text_content = strip_tags(html_content)  # Generate plain text version
            
            # Create email
            subject = 'Reset Your NerdsLab Password'
            from_email = settings.DEFAULT_FROM_EMAIL
            to = [email]
            
            msg = EmailMultiAlternatives(subject, text_content, from_email, to)
            msg.attach_alternative(html_content, "text/html")
            
            # Send email
            msg.send()
            
            return Response({'message': 'Password reset email sent'})
        except User.DoesNotExist:
            # Don't reveal if email exists or not
            return Response({'message': 'Password reset email sent if email exists'})
        except Exception as e:
            import traceback
            print(f"Error: {str(e)}")
            print(traceback.format_exc())
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
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
        from django.core.cache import cache
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
        from django.core.cache import cache
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