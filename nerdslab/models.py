from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model

User = get_user_model()

class LabFlag(models.Model):
    LAB_CHOICES = [
        ('feedme', 'FeedMe XSS Lab'),
        ('mediconnect', 'MediConnect SQL Injection Lab'),
    ]

    lab_id = models.CharField(max_length=50, choices=LAB_CHOICES)
    flag_format = models.CharField(max_length=100)
    flag_value = models.CharField(max_length=100)
    created_at = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ('lab_id', 'flag_value')

    def __str__(self):
        return f"{self.lab_id} - {self.flag_format}"

class LabSubmission(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    lab = models.ForeignKey(LabFlag, on_delete=models.CASCADE)
    submitted_flag = models.CharField(max_length=100)
    is_correct = models.BooleanField(default=False)
    submitted_at = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = ('user', 'lab')

    def __str__(self):
        return f"{self.user.username} - {self.lab.lab_id}" 