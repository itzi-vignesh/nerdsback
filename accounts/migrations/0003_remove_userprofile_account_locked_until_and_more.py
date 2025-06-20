# Generated by Django 4.2.1 on 2025-04-19 06:39

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_userprofile_account_locked_until_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userprofile',
            name='account_locked_until',
        ),
        migrations.RemoveField(
            model_name='userprofile',
            name='failed_login_attempts',
        ),
        migrations.RemoveField(
            model_name='userprofile',
            name='is_email_verified',
        ),
        migrations.RemoveField(
            model_name='userprofile',
            name='last_failed_login',
        ),
        migrations.RemoveField(
            model_name='userprofile',
            name='tfa_enabled',
        ),
        migrations.RemoveField(
            model_name='userprofile',
            name='tfa_secret',
        ),
        migrations.DeleteModel(
            name='LoginAttempt',
        ),
    ]
