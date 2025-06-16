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

class UserLab(models.Model):
    """Model for tracking user's assigned labs and their flags."""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='labs')
    lab_id = models.CharField(max_length=100)
    assigned_at = models.DateTimeField(auto_now_add=True)
    flag = models.CharField(max_length=255)  # Store the correct flag
    attempts = models.IntegerField(default=0)
    last_attempt = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        unique_together = ('user', 'lab_id')
        
    def verify_flag(self, submitted_flag):
        """Verify if the submitted flag is correct."""
        self.attempts += 1
        self.last_attempt = timezone.now()
        self.save()
        return submitted_flag == self.flag
    
    def __str__(self):
        return f"{self.user.username} - {self.lab_id}"

class UserLabProgress(models.Model):
    """Model for tracking user's progress in labs."""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='lab_progress')
    lab_id = models.CharField(max_length=100)
    started_at = models.DateTimeField(auto_now_add=True)
    completed = models.BooleanField(default=False)
    completed_at = models.DateTimeField(null=True, blank=True)
    last_attempt = models.DateTimeField(null=True, blank=True)
    score = models.IntegerField(default=0)
    
    class Meta:
        unique_together = ('user', 'lab_id')
        verbose_name_plural = 'User lab progress'
    
    def mark_completed(self, score=None):
        """Mark the lab as completed."""
        self.completed = True
        self.completed_at = timezone.now()
        if score is not None:
            self.score = score
        self.save()
    
    def __str__(self):
        return f"{self.user.username} - {self.lab_id} ({'Completed' if self.completed else 'In Progress'})"

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