from django.db import models
from django.contrib.auth.models import User
import uuid
from django.utils import timezone
from datetime import timedelta

# We're using Django's built-in User model for authentication
# If you need to extend the User model, you can create a profile model:

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField(blank=True, null=True)
    profile_image = models.CharField(max_length=255, blank=True, null=True)
    date_joined = models.DateTimeField(default=timezone.now)
    
    def __str__(self):
        return self.user.username

class PasswordResetToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_tokens')
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    def save(self, *args, **kwargs):
        # Set expiration to 24 hours from creation if not already set
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(hours=24)
        super().save(*args, **kwargs)
    
    def is_valid(self):
        """Check if the token is valid (not expired and not used)"""
        return not self.is_used and timezone.now() < self.expires_at
    
    def __str__(self):
        return f"Password reset token for {self.user.username}"

class EmailVerificationToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='email_verification_tokens')
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    def save(self, *args, **kwargs):
        # Set expiration to 48 hours from creation if not already set
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(hours=48)
        super().save(*args, **kwargs)
    
    def is_valid(self):
        """Check if the token is valid (not expired and not used)"""
        return not self.is_used and timezone.now() < self.expires_at
    
    def __str__(self):
        return f"Email verification token for {self.user.username}" 