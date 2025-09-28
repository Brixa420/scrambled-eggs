""
Email service for sending various types of emails.
"""
import logging
from typing import Optional, Dict, Any, List, Union
from flask import current_app, render_template
from flask_mail import Message
from app.extensions import mail

logger = logging.getLogger(__name__)

class EmailService:
    """
    Service for sending various types of emails.
    """
    
    @staticmethod
    def send_email(
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
            True if the email was sent successfully, False otherwise
        """
        if not current_app.config.get('MAIL_SERVER'):
            logger.warning("Email not configured, not sending email")
            return False
        
        try:
            # Render the email body from a template
            html_body = render_template(f'emails/{template}.html', **template_vars)
            text_body = render_template(f'emails/{template}.txt', **template_vars)
            
            # Create the email message
            msg = Message(
                subject=subject,
                recipients=[to] if isinstance(to, str) else to,
                html=html_body,
                body=text_body
            )
            
            # Set the sender
            msg.sender = current_app.config.get('MAIL_DEFAULT_SENDER')
            
            # Send the email
            mail.send(msg)
            
            logger.info(f"Email sent to {to} with subject: {subject}")
            return True
            
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
        verification_url = f"{current_app.config['FRONTEND_URL']}/verify-email?token={token}"
        
        return cls.send_email(
            to=email,
            subject="Verify Your Email Address",
            template='verify_email',
            verification_url=verification_url,
            app_name=current_app.config.get('APP_NAME', 'Our App')
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
