import os
from django.conf import settings
from django.core.mail import get_connection, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import logging
from threading import Thread
import time
from smtplib import SMTPException, SMTPAuthenticationError, SMTPConnectError
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
            # Log email attempt
            logger.info(f"Attempting to send email to {to_email}")
            logger.info(f"Using SMTP settings: {settings.EMAIL_HOST}:{settings.EMAIL_PORT}")
            
            # Prepare email content
            html_content = render_to_string(template_name, context)
            text_content = strip_tags(html_content)

            # Create email message
            msg = EmailMultiAlternatives(
                subject,
                text_content,
                from_email,
                [to_email],
                connection=get_connection(
                    host=settings.EMAIL_HOST,
                    port=settings.EMAIL_PORT,
                    username=settings.EMAIL_HOST_USER,
                    password=settings.EMAIL_HOST_PASSWORD,
                    use_tls=settings.EMAIL_USE_TLS,
                    timeout=settings.EMAIL_TIMEOUT
                )
            )
            msg.attach_alternative(html_content, "text/html")

            # Implement retry mechanism
            max_retries = getattr(settings, 'SMTP_MAX_RETRIES', 3)
            retry_delay = getattr(settings, 'SMTP_RETRY_DELAY', 2)

            for attempt in range(max_retries):
                try:
                    msg.send()
                    logger.info(f"Email sent successfully to {to_email}")
                    return
                except SMTPAuthenticationError as e:
                    logger.error(f"SMTP Authentication failed: {str(e)}")
                    raise  # Don't retry on auth failure
                except SMTPConnectError as e:
                    logger.error(f"SMTP Connection failed (attempt {attempt + 1}): {str(e)}")
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                    else:
                        raise
                except (SMTPException, SocketTimeout) as e:
                    logger.warning(f"Email sending failed (attempt {attempt + 1}): {str(e)}")
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                    else:
                        logger.error(f"All email sending attempts failed for {to_email}: {str(e)}")
                        raise
                except Exception as e:
                    logger.error(f"Unexpected error sending email to {to_email}: {str(e)}")
                    raise

        except Exception as e:
            logger.error(f"Error preparing/sending email to {to_email}: {str(e)}")
            raise

    # Start email sending in background
    Thread(target=send).start()

def send_verification_email(user, token):
    """
    Send verification email to user
    """
    try:
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
        logger.info(f"Verification email queued for {user.email}")
    except Exception as e:
        logger.error(f"Failed to queue verification email for {user.email}: {str(e)}")
        raise

def send_password_reset_email(user, token):
    """
    Send password reset email to user
    """
    try:
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
        logger.info(f"Password reset email queued for {user.email}")
    except Exception as e:
        logger.error(f"Failed to queue password reset email for {user.email}: {str(e)}")
        raise 