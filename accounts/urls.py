from django.urls import path
from rest_framework.authtoken.views import obtain_auth_token
from . import views
from .views import (
    RegisterView, 
    LoginView, 
    LogoutView, 
    UserDetailView, 
    PasswordResetRequestView, 
    PasswordResetConfirmView,
    ChangePasswordView,
    EmailVerificationView,
    ResendVerificationEmailView
)

urlpatterns = [
    # Authentication endpoints
    path('login/', LoginView.as_view(), name='login'),
    path('register/', RegisterView.as_view(), name='register'),
    path('me/', UserDetailView.as_view(), name='user-detail'),
    path('logout/', LogoutView.as_view(), name='logout'),
    
    # Password reset endpoints
    path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('verify-email/', EmailVerificationView.as_view(), name='verify-email'),
    path('resend-verification/', ResendVerificationEmailView.as_view(), name='resend-verification'),
]