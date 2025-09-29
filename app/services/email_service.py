""
Email service for sending various types of emails.
"""
import logging
from typing import Optional, Dict, Any, List, Union
from flask import current_app, render_template, has_app_context
from flask_mail import Message
from app.extensions import mail

# Default configuration values
DEFAULT_CONFIG = {
    'FRONTEND_URL': 'http://localhost:3000',
    'APP_NAME': 'Scrambled Eggs',
    'MAIL_DEFAULT_SENDER': 'noreply@scrambled-eggs.dev'
}

logger = logging.getLogger(__name__)
class EmailService:
    """
    Service for sending various types of emails.
    """
    
    @classmethod
    def send_email(
        cls,
        to: Union[str, List[str]],
        subject: str,
        template: str,
        **template_vars
    ) -> bool:
        """
        Send an email using a template.
        
        Args:
            to: Email recipient(s)
            subject: Email subject
            template: Template name (without extension)
            **template_vars: Variables to pass to the template
            
        Returns:
            bool: True if email was sent successfully, False otherwise
        """
        try:
            # Get configuration with fallback to defaults
            config = {**DEFAULT_CONFIG}
            if has_app_context():
                config.update({
                    'MAIL_DEFAULT_SENDER': current_app.config.get('MAIL_DEFAULT_SENDER', config['MAIL_DEFAULT_SENDER'])
                })
            
            # Ensure we have a sender
            sender = config['MAIL_DEFAULT_SENDER']
            
            # Create message
            msg = Message(
                subject=subject,
                sender=sender,
                recipients=[to] if isinstance(to, str) else to,
            )
            
            # Render email body from template if we have an app context
            if has_app_context():
                try:
                    with current_app.app_context():
                        msg.html = render_template(f'emails/{template}.html', **template_vars)
                        msg.body = render_template(f'emails/{template}.txt', **template_vars)
                except Exception as e:
                    logger.warning(f"Could not render email template: {str(e)}")
                    # If template rendering fails, use a simple text email
                    msg.body = f"Please enable HTML to view this email.\n\n{template_vars}"
            else:
                # Fallback for non-app context
                msg.body = f"Subject: {subject}\n\n{template_vars}"
            
            # Send email if we have a mail instance
            if mail and hasattr(mail, 'send'):
                with current_app.app_context():
                    mail.send(msg)
                return True
            else:
                logger.warning("Mail extension not initialized, email not sent")
                return False
            
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}", exc_info=True)
            return False
    
    @classmethod
    def send_verification_email(cls, email: str, token: str) -> bool:
        """
        Send an email verification email.
        
        Args:
            email: The recipient's email address
            token: The verification token
            
        Returns:
            True if the email was sent successfully, False otherwise
        """
        # Get configuration with fallback to defaults
        config = {**DEFAULT_CONFIG}
        if has_app_context():
            config.update({
                'FRONTEND_URL': current_app.config.get('FRONTEND_URL', config['FRONTEND_URL']),
                'APP_NAME': current_app.config.get('APP_NAME', config['APP_NAME']),
                'MAIL_DEFAULT_SENDER': current_app.config.get('MAIL_DEFAULT_SENDER', config['MAIL_DEFAULT_SENDER'])
            })
        
        verification_url = f"{config['FRONTEND_URL']}/verify-email?token={token}"
        
        return cls.send_email(
            to=email,
            subject="Verify Your Email Address",
            template='verify_email',
            verification_url=verification_url,
            app_name=config['APP_NAME']
        )
    
    @classmethod
    def send_password_reset_email(cls, email: str, token: str) -> bool:
        """
        Send a password reset email.
        
        Args:
            email: The recipient's email address
            token: The password reset token
            
        Returns:
            True if the email was sent successfully, False otherwise
        """
        reset_url = f"{current_app.config['FRONTEND_URL']}/reset-password?token={token}"
        
        return cls.send_email(
            to=email,
            subject="Reset Your Password",
            template='reset_password',
            reset_url=reset_url,
            app_name=current_app.config.get('APP_NAME', 'Our App')
        )
    
    @classmethod
    def send_welcome_email(cls, email: str, username: str) -> bool:
        """
        Send a welcome email to a new user.
        
        Args:
            email: The recipient's email address
            username: The user's username
            
        Returns:
            True if the email was sent successfully, False otherwise
        """
        return cls.send_email(
            to=email,
            subject="Welcome to Our App!",
            template='welcome',
            username=username,
            app_name=current_app.config.get('APP_NAME', 'Our App'),
            support_email=current_app.config.get('MAIL_SUPPORT_EMAIL')
        )
    
    @classmethod
    def send_file_shared_notification(
        cls,
        email: str,
        filename: str,
        shared_by: str,
        download_url: str
    ) -> bool:
        """
        Send a notification when a file is shared with a user.
        
        Args:
            email: The recipient's email address
            filename: The name of the shared file
            shared_by: The name of the user who shared the file
            download_url: URL to download the file
            
        Returns:
            True if the email was sent successfully, False otherwise
        """
        return cls.send_email(
            to=email,
            subject=f"{shared_by} shared a file with you",
            template='file_shared',
            filename=filename,
            shared_by=shared_by,
            download_url=download_url,
            app_name=current_app.config.get('APP_NAME', 'Our App')
        )
    
    @classmethod
    def send_download_notification(
        cls,
        email: str,
        filename: str,
        downloaded_by: str,
        download_time: str
    ) -> bool:
        """
        Send a notification when a file is downloaded.
        
        Args:
            email: The recipient's email address
            filename: The name of the downloaded file
            downloaded_by: The name of the user who downloaded the file
            download_time: When the file was downloaded
            
        Returns:
            True if the email was sent successfully, False otherwise
        """
        return cls.send_email(
            to=email,
            subject=f"Your file was downloaded",
            template='file_downloaded',
            filename=filename,
            downloaded_by=downloaded_by,
            download_time=download_time,
            app_name=current_app.config.get('APP_NAME', 'Our App')
        )
    
    @classmethod
    def send_admin_notification(
        cls,
        subject: str,
        message: str,
        level: str = 'info',
        context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Send a notification to the admin email.
        
        Args:
            subject: Email subject
            message: The main message content
            level: Notification level ('info', 'warning', 'error')
            context: Additional context data
            
        Returns:
            True if the email was sent successfully, False otherwise
        """
        admin_email = current_app.config.get('MAIL_ADMIN_EMAIL')
        if not admin_email:
            logger.warning("No admin email configured, not sending admin notification")
            return False
            
        return cls.send_email(
            to=admin_email,
            subject=f"[{level.upper()}] {subject}",
            template='admin_notification',
            message=message,
            level=level,
            context=context or {},
            app_name=current_app.config.get('APP_NAME', 'Our App')
        )

# Create a singleton instance
email_service = EmailService()

# Add convenience functions for backward compatibility
def send_verification_email(email: str, token: str) -> bool:
    return email_service.send_verification_email(email, token)

def send_password_reset_email(email: str, token: str) -> bool:
    return email_service.send_password_reset_email(email, token)

def send_welcome_email(email: str, username: str) -> bool:
    return email_service.send_welcome_email(email, username)
