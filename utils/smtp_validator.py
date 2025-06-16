import asyncio
import aiosmtplib
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from concurrent.futures import ThreadPoolExecutor
import time

logger = logging.getLogger(__name__)

class SMTPValidator:
    """SMTP validation utility with async support."""
    
    def __init__(self, timeout=30):
        self.timeout = timeout
        self.executor = ThreadPoolExecutor(max_workers=5)
    
    async def validate_smtp_async(self, email, password, smtp_host, smtp_port, smtp_username=None, provider='custom'):
        """Async SMTP validation using aiosmtplib."""
        if not smtp_username:
            smtp_username = email
        
        try:
            # Create SMTP connection
            if smtp_port == 465:
                smtp = aiosmtplib.SMTP(hostname=smtp_host, port=smtp_port, use_tls=True)
            else:
                smtp = aiosmtplib.SMTP(hostname=smtp_host, port=smtp_port)
            
            # Connect and authenticate
            await smtp.connect()
            if smtp_port != 465:
                await smtp.starttls()
            
            await smtp.login(smtp_username, password)
            
            # Send test email
            test_msg = self._create_test_message(email, smtp_host, smtp_port, smtp_username, provider)
            
            await smtp.send_message(test_msg)
            await smtp.quit()
            
            logger.info(f"SMTP validation successful for {email}")
            
            return {
                'success': True,
                'message': f'✅ SMTP validation successful! Test email sent to {email}',
                'details': f'Connected to {smtp_host}:{smtp_port}',
                'provider': provider,
                'response_time': None
            }
            
        except aiosmtplib.SMTPAuthenticationError as e:
            logger.warning(f"SMTP authentication failed for {email}: {str(e)}")
            return {
                'success': False,
                'message': f'❌ SMTP Authentication failed: {str(e)}. Check username and password.',
                'error_type': 'auth_error',
                'suggestions': self._get_auth_suggestions(provider)
            }
        except aiosmtplib.SMTPConnectError as e:
            logger.warning(f"SMTP connection failed for {email}: {str(e)}")
            return {
                'success': False,
                'message': f'❌ Could not connect to SMTP server {smtp_host}:{smtp_port}. Error: {str(e)}',
                'error_type': 'connection_error',
                'suggestions': ['Check SMTP host and port', 'Verify network connectivity', 'Check firewall settings']
            }
        except Exception as e:
            logger.error(f"SMTP validation error for {email}: {str(e)}")
            return {
                'success': False,
                'message': f'❌ SMTP test failed: {str(e)}',
                'error_type': 'general_error'
            }
    
    def validate_smtp_sync(self, email, password, smtp_host, smtp_port, smtp_username=None, provider='custom'):
        """Synchronous SMTP validation using smtplib."""
        if not smtp_username:
            smtp_username = email
        
        start_time = time.time()
        
        try:
            # Test SMTP connection
            if smtp_port == 465:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(smtp_host, smtp_port, context=context, timeout=self.timeout)
            else:
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=self.timeout)
                server.starttls()
            
            # Authenticate
            server.login(smtp_username, password)
            
            # Send test email
            test_msg = self._create_test_message(email, smtp_host, smtp_port, smtp_username, provider)
            
            server.send_message(test_msg)
            server.quit()
            
            response_time = round(time.time() - start_time, 2)
            logger.info(f"SMTP validation successful for {email} in {response_time}s")
            
            return {
                'success': True,
                'message': f'✅ SMTP validation successful! Test email sent to {email}',
                'details': f'Connected to {smtp_host}:{smtp_port}',
                'provider': provider,
                'response_time': f'{response_time}s'
            }
            
        except smtplib.SMTPAuthenticationError as e:
            logger.warning(f"SMTP authentication failed for {email}: {str(e)}")
            return {
                'success': False,
                'message': f'❌ SMTP Authentication failed: {str(e)}. Check username and password.',
                'error_type': 'auth_error',
                'suggestions': self._get_auth_suggestions(provider)
            }
        except smtplib.SMTPConnectError as e:
            logger.warning(f"SMTP connection failed for {email}: {str(e)}")
            return {
                'success': False,
                'message': f'❌ Could not connect to SMTP server {smtp_host}:{smtp_port}. Error: {str(e)}',
                'error_type': 'connection_error',
                'suggestions': ['Check SMTP host and port', 'Verify network connectivity', 'Check firewall settings']
            }
        except Exception as e:
            logger.error(f"SMTP validation error for {email}: {str(e)}")
            return {
                'success': False,
                'message': f'❌ SMTP test failed: {str(e)}',
                'error_type': 'general_error'
            }
    
    def validate_smtp_threaded(self, email, password, smtp_host, smtp_port, smtp_username=None, provider='custom'):
        """Run sync validation in thread pool."""
        future = self.executor.submit(
            self.validate_smtp_sync, 
            email, password, smtp_host, smtp_port, smtp_username, provider
        )
        return future.result(timeout=self.timeout)
    
    def _create_test_message(self, email, smtp_host, smtp_port, smtp_username, provider):
        """Create test email message."""
        test_msg = MIMEText(f"""
🎉 SMTP Configuration Validated Successfully!

Your email account ({email}) is properly configured and ready for email warmup campaigns.

✅ Test Details:
- SMTP Server: {smtp_host}:{smtp_port}
- Username: {smtp_username}
- Provider: {provider.upper()}
- Validation Time: {time.strftime('%Y-%m-%d %H:%M:%S')}

🚀 Next Steps:
1. Create your email warmup campaign
2. Set your daily volume limits
3. Start warming up your sender reputation

You can now proceed with creating your email warmup campaign with confidence!

---
📧 Email Warmup System
Improving your email deliverability one send at a time.
        """)
        
        test_msg['From'] = email
        test_msg['To'] = email
        test_msg['Subject'] = "✅ SMTP Validation Successful - Email Warmup System"
        
        return test_msg
    
    def _get_auth_suggestions(self, provider):
        """Get authentication suggestions based on provider."""
        suggestions = {
            'gmail': [
                'Enable 2-Factor Authentication on your Google account',
                'Generate an App Password (not your regular password)',
                'Use the App Password in the SMTP password field',
                'Make sure "Less secure app access" is disabled (use App Password instead)'
            ],
            'outlook': [
                'Use your regular email and password',
                'If 2FA is enabled, generate an App Password',
                'Check Microsoft account security settings'
            ],
            'yahoo': [
                'Enable 2-Factor Authentication',
                'Generate App Password for Mail applications',
                'Use the App Password instead of your regular password'
            ],
            'aws_ses': [
                'Use SMTP credentials from AWS SES console',
                'Verify your domain/email in AWS SES',
                'Check AWS SES sending limits'
            ]
        }
        
        return suggestions.get(provider, [
            'Check your email provider\'s SMTP settings',
            'Verify your username and password',
            'Check if your email provider requires App Passwords'
        ])

# Global validator instance
smtp_validator = SMTPValidator()

# Convenience functions
def validate_smtp_async(email, password, smtp_host, smtp_port, smtp_username=None, provider='custom'):
    """Async SMTP validation."""
    return smtp_validator.validate_smtp_async(email, password, smtp_host, smtp_port, smtp_username, provider)

def validate_smtp_sync(email, password, smtp_host, smtp_port, smtp_username=None, provider='custom'):
    """Sync SMTP validation."""
    return smtp_validator.validate_smtp_sync(email, password, smtp_host, smtp_port, smtp_username, provider)

def validate_smtp_threaded(email, password, smtp_host, smtp_port, smtp_username=None, provider='custom'):
    """Threaded SMTP validation."""
    return smtp_validator.validate_smtp_threaded(email, password, smtp_host, smtp_port, smtp_username, provider)
