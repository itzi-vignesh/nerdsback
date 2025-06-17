from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

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

# Remove unwanted lab-related models
# class LabFlag(models.Model):
#     ...
# class LabSubmission(models.Model):
#     ... 