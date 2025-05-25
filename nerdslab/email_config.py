import os
from django.conf import settings
from django.core.mail import get_connection, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import logging
from threading import Thread
import time
from smtplib import SMTPException
from socket import timeout as SocketTimeout

logger = logging.getLogger('accounts')

def send_email_async(subject, to_email, template_name, context, from_email=None):
    """
    Send email asynchronously using a background thread
    """
    if from_email is None:
        from_email = settings.DEFAULT_FROM_EMAIL

    def send():
        try:
            html_content = render_to_string(template_name, context)
            text_content = strip_tags(html_content)

            msg = EmailMultiAlternatives(
                subject,
                text_content,
                from_email,
                [to_email],
                connection=get_connection(timeout=settings.EMAIL_TIMEOUT)
            )
            msg.attach_alternative(html_content, "text/html")

            # Implement retry mechanism
            for attempt in range(settings.SMTP_MAX_RETRIES):
                try:
                    msg.send()
                    logger.info(f"Email sent successfully to {to_email}")
                    return
                except (SMTPException, SocketTimeout) as e:
                    if attempt < settings.SMTP_MAX_RETRIES - 1:
                        logger.warning(f"Email sending failed (attempt {attempt + 1}): {str(e)}")
                        time.sleep(settings.SMTP_RETRY_DELAY)
                    else:
                        logger.error(f"All email sending attempts failed for {to_email}: {str(e)}")
                except Exception as e:
                    logger.error(f"Unexpected error sending email to {to_email}: {str(e)}")
                    break

        except Exception as e:
            logger.error(f"Error preparing email for {to_email}: {str(e)}")

    # Start email sending in background
    Thread(target=send).start()

def send_verification_email(user, token):
    """
    Send verification email to user
    """
    verify_url = f"{settings.FRONTEND_URL}/verify-email?token={token.token}"
    context = {
        'verify_url': verify_url,
        'user': user,
        'expiry_hours': 48,
    }
    
    send_email_async(
        subject='Verify Your NerdsLab Account',
        to_email=user.email,
        template_name='emails/email_verification.html',
        context=context
    )

def send_password_reset_email(user, token):
    """
    Send password reset email to user
    """
    reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token.token}"
    context = {
        'reset_url': reset_url,
        'user': user,
        'expiry_hours': 24,
    }
    
    send_email_async(
        subject='Reset Your NerdsLab Password',
        to_email=user.email,
        template_name='emails/password_reset.html',
        context=context
    ) 