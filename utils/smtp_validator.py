# KEXY Email Warmup System - SMTP Validator
# CORRECTED: Preserves all existing functionality + adds Amazon SES validation

import smtplib
import ssl
import re
import logging
from typing import Tuple, Dict, Any

logger = logging.getLogger(__name__)

class SMTPValidator:
    """
    SMTP connection validator for various email providers including Amazon SES
    Preserves all existing functionality while adding comprehensive SES support
    """
    
    def __init__(self):
        # CORRECTED: Enhanced provider configurations with Amazon SES
        self.provider_configs = {
            # Original providers (Preserved)
            'gmail': {
                'host': 'smtp.gmail.com',
                'port': 587,
                'use_tls': True,
                'requires_auth': True,
                'validation_regex': r'^[a-zA-Z0-9._%+-]+@gmail\.com$',
                'help_text': 'Gmail requires 2FA and App Password'
            },
            'outlook': {
                'host': 'smtp-mail.outlook.com',
                'port': 587,
                'use_tls': True,
                'requires_auth': True,
                'validation_regex': r'^[a-zA-Z0-9._%+-]+@(outlook|hotmail|live)\.com$',
                'help_text': 'Outlook requires 2FA and App Password'
            },
            'yahoo': {
                'host': 'smtp.mail.yahoo.com',
                'port': 587,
                'use_tls': True,
                'requires_auth': True,
                'validation_regex': r'^[a-zA-Z0-9._%+-]+@yahoo\.com$',
                'help_text': 'Yahoo requires 2FA and App Password'
            },
            'custom_smtp': {
                'host': None,  # User-defined
                'port': 587,
                'use_tls': True,
                'requires_auth': True,
                'validation_regex': None,
                'help_text': 'Custom SMTP: Provide your own settings'
            },

            # ADDED: Amazon SES regional configurations
            'amazon_ses_us_east_1': {
                'host': 'email-smtp.us-east-1.amazonaws.com',
                'port': 587,
                'use_tls': True,
                'requires_auth': True,
                'region': 'us-east-1',
                'service': 'ses',
                'validation_regex': None,  # SES can send from any verified domain
                'help_text': 'Amazon SES US East 1: Requires IAM credentials'
            },
            'amazon_ses_us_west_2': {
                'host': 'email-smtp.us-west-2.amazonaws.com',
                'port': 587,
                'use_tls': True,
                'requires_auth': True,
                'region': 'us-west-2',
                'service': 'ses',
                'validation_regex': None,
                'help_text': 'Amazon SES US West 2: Requires IAM credentials'
            },
            'amazon_ses_us_west_1': {
                'host': 'email-smtp.us-west-1.amazonaws.com',
                'port': 587,
                'use_tls': True,
                'requires_auth': True,
                'region': 'us-west-1',
                'service': 'ses',
                'validation_regex': None,
                'help_text': 'Amazon SES US West 1: Requires IAM credentials'
            },
            'amazon_ses_eu_west_1': {
                'host': 'email-smtp.eu-west-1.amazonaws.com',
                'port': 587,
                'use_tls': True,
                'requires_auth': True,
                'region': 'eu-west-1',
                'service': 'ses',
                'validation_regex': None,
                'help_text': 'Amazon SES EU West 1: Requires IAM credentials'
            },
            'amazon_ses_eu_central_1': {
                'host': 'email-smtp.eu-central-1.amazonaws.com',
                'port': 587,
                'use_tls': True,
                'requires_auth': True,
                'region': 'eu-central-1',
                'service': 'ses',
                'validation_regex': None,
                'help_text': 'Amazon SES EU Central 1: Requires IAM credentials'
            },
            'amazon_ses_ap_southeast_1': {
                'host': 'email-smtp.ap-southeast-1.amazonaws.com',
                'port': 587,
                'use_tls': True,
                'requires_auth': True,
                'region': 'ap-southeast-1',
                'service': 'ses',
                'validation_regex': None,
                'help_text': 'Amazon SES Asia Pacific Singapore: Requires IAM credentials'
            },
            'amazon_ses_ap_southeast_2': {
                'host': 'email-smtp.ap-southeast-2.amazonaws.com',
                'port': 587,
                'use_tls': True,
                'requires_auth': True,
                'region': 'ap-southeast-2',
                'service': 'ses',
                'validation_regex': None,
                'help_text': 'Amazon SES Asia Pacific Sydney: Requires IAM credentials'
            },
            'amazon_ses_ap_northeast_1': {
                'host': 'email-smtp.ap-northeast-1.amazonaws.com',
                'port': 587,
                'use_tls': True,
                'requires_auth': True,
                'region': 'ap-northeast-1',
                'service': 'ses',
                'validation_regex': None,
                'help_text': 'Amazon SES Asia Pacific Tokyo: Requires IAM credentials'
            },
            'amazon_ses_ca_central_1': {
                'host': 'email-smtp.ca-central-1.amazonaws.com',
                'port': 587,
                'use_tls': True,
                'requires_auth': True,
                'region': 'ca-central-1',
                'service': 'ses',
                'validation_regex': None,
                'help_text': 'Amazon SES Canada Central: Requires IAM credentials'
            },
            'custom_ses': {
                'host': None,  # User-defined
                'port': 587,
                'use_tls': True,
                'requires_auth': True,
                'service': 'ses',
                'validation_regex': None,
                'help_text': 'Custom Amazon SES: Provide your regional endpoint'
            }
        }

    def validate_provider_credentials(self, provider: str, email: str, username: str, password: str, 
                                    smtp_host: str = None, smtp_port: int = 587, use_tls: bool = True) -> Tuple[bool, str]:
        """
        Validate SMTP credentials for various providers including Amazon SES
        
        Args:
            provider: Email provider identifier
            email: Email address
            username: SMTP username (or Access Key ID for SES)
            password: SMTP password (or Secret Access Key for SES)
            smtp_host: Custom SMTP host (optional)
            smtp_port: SMTP port (default: 587)
            use_tls: Whether to use TLS (default: True)
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # Get provider configuration
            config = self.provider_configs.get(provider)
            if not config:
                return False, f"Unsupported provider: {provider}"

            # Validate input data
            validation_result = self._validate_input_data(provider, email, username, password, config)
            if not validation_result[0]:
                return validation_result

            # Use custom host if provided, otherwise use provider default
            host = smtp_host if smtp_host else config.get('host')
            if not host:
                return False, f"SMTP host not configured for provider: {provider}"

            port = smtp_port or config.get('port', 587)

            # ADDED: Amazon SES specific validation
            if self._is_amazon_ses(provider):
                return self._validate_ses_connection(host, port, username, password, use_tls, provider)

            # Original SMTP validation (Preserved)
            return self._validate_standard_smtp(host, port, username, password, use_tls, provider)

        except Exception as e:
            logger.error(f"SMTP validation error for {provider}: {str(e)}")
            return False, f"Validation error: {str(e)}"

    def _validate_input_data(self, provider: str, email: str, username: str, password: str, config: Dict) -> Tuple[bool, str]:
        """Validate input data format and requirements"""
        
        # Check required fields
        if not all([provider, email, username, password]):
            return False, "All fields are required"

        # Validate email format
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            return False, "Invalid email format"

        # Provider-specific email validation (for non-SES providers)
        if config.get('validation_regex') and not re.match(config['validation_regex'], email):
            return False, f"Email format not supported for {provider}"

        # ADDED: Amazon SES specific validations
        if self._is_amazon_ses(provider):
            return self._validate_ses_credentials_format(username, password)

        return True, "Input validation passed"

    def _is_amazon_ses(self, provider: str) -> bool:
        """Check if provider is Amazon SES"""
        return 'amazon_ses' in provider or provider == 'custom_ses'

    def _validate_ses_credentials_format(self, access_key_id: str, secret_access_key: str) -> Tuple[bool, str]:
        """Validate Amazon SES credentials format"""
        
        # Validate Access Key ID format
        if not access_key_id.startswith('AKIA'):
            return False, "Invalid AWS Access Key ID format (should start with 'AKIA')"
        
        if len(access_key_id) != 20:
            return False, "Invalid AWS Access Key ID length (should be 20 characters)"

        # Validate Secret Access Key format
        if len(secret_access_key) < 20:
            return False, "Invalid AWS Secret Access Key (should be at least 20 characters)"

        # Check for common AWS credential patterns
        if not re.match(r'^[A-Za-z0-9+/]+$', secret_access_key):
            return False, "Invalid AWS Secret Access Key format"

        return True, "SES credentials format validation passed"

    def _validate_ses_connection(self, host: str, port: int, access_key_id: str, 
                                secret_access_key: str, use_tls: bool, provider: str) -> Tuple[bool, str]:
        """
        Validate Amazon SES SMTP connection
        """
        try:
            logger.info(f"Testing SES connection to {host}:{port}")
            
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect to SES SMTP endpoint
            with smtplib.SMTP(host, port, timeout=30) as server:
                server.set_debuglevel(0)  # Disable debug output in production
                
                if use_tls:
                    server.starttls(context=context)
                    logger.info("TLS connection established")

                # Authenticate with SES using IAM credentials
                server.login(access_key_id, secret_access_key)
                logger.info("SES authentication successful")

                # Test connection with NOOP command
                status, message = server.noop()
                if status == 250:
                    return True, f"Amazon SES connection successful ({provider})"
                else:
                    return False, f"SES connection test failed: {message}"

        except smtplib.SMTPAuthenticationError as e:
            error_code = str(e).split()[0] if str(e).split() else "Unknown"
            if "535" in error_code:
                return False, f"SES Authentication failed: Invalid IAM credentials. Error: {str(e)}"
            else:
                return False, f"SES Authentication error: {str(e)}"
        
        except smtplib.SMTPConnectError as e:
            return False, f"SES Connection failed: Unable to connect to {host}:{port}. Error: {str(e)}"
        
        except smtplib.SMTPException as e:
            return False, f"SES SMTP error: {str(e)}"
        
        except ssl.SSLError as e:
            return False, f"SES SSL/TLS error: {str(e)}"
        
        except Exception as e:
            return False, f"SES connection error: {str(e)}"

    def _validate_standard_smtp(self, host: str, port: int, username: str, 
                               password: str, use_tls: bool, provider: str) -> Tuple[bool, str]:
        """
        Validate standard SMTP connection (Preserved original functionality)
        """
        try:
            logger.info(f"Testing SMTP connection to {host}:{port}")
            
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect to SMTP server
            with smtplib.SMTP(host, port, timeout=30) as server:
                server.set_debuglevel(0)  # Disable debug output in production
                
                if use_tls:
                    server.starttls(context=context)
                    logger.info("TLS connection established")

                # Authenticate
                server.login(username, password)
                logger.info("SMTP authentication successful")

                # Test connection
                status, message = server.noop()
                if status == 250:
                    return True, f"SMTP connection successful ({provider})"
                else:
                    return False, f"SMTP connection test failed: {message}"

        except smtplib.SMTPAuthenticationError as e:
            error_msg = f"Authentication failed for {provider}: {str(e)}"
            if provider in ['gmail', 'outlook', 'yahoo']:
                error_msg += " (Ensure 2FA is enabled and you're using an App Password)"
            return False, error_msg
        
        except smtplib.SMTPConnectError as e:
            return False, f"Connection failed to {host}:{port}: {str(e)}"
        
        except smtplib.SMTPException as e:
            return False, f"SMTP error for {provider}: {str(e)}"
        
        except ssl.SSLError as e:
            return False, f"SSL/TLS error: {str(e)}"
        
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def get_provider_info(self, provider: str) -> Dict[str, Any]:
        """Get provider configuration information"""
        config = self.provider_configs.get(provider, {})
        return {
            'provider': provider,
            'host': config.get('host'),
            'port': config.get('port'),
            'use_tls': config.get('use_tls'),
            'requires_auth': config.get('requires_auth'),
            'help_text': config.get('help_text'),
            'region': config.get('region'),
            'service': config.get('service')
        }

    def get_supported_providers(self) -> list:
        """Get list of all supported providers"""
        return list(self.provider_configs.keys())

    def test_connection_comprehensive(self, provider: str, email: str, username: str, password: str,
                                    smtp_host: str = None, smtp_port: int = 587, use_tls: bool = True) -> Dict[str, Any]:
        """
        Comprehensive connection test with detailed results
        """
        result = {
            'provider': provider,
            'success': False,
            'message': '',
            'details': {},
            'recommendations': []
        }

        try:
            # Basic validation
            success, message = self.validate_provider_credentials(
                provider, email, username, password, smtp_host, smtp_port, use_tls
            )
            
            result['success'] = success
            result['message'] = message
            
            # Add provider-specific details
            config = self.provider_configs.get(provider, {})
            result['details'] = {
                'host': smtp_host or config.get('host'),
                'port': smtp_port,
                'use_tls': use_tls,
                'is_ses': self._is_amazon_ses(provider),
                'region': config.get('region')
            }
            
            # Add recommendations based on provider and result
            if not success:
                result['recommendations'] = self._get_troubleshooting_recommendations(provider, message)
            
        except Exception as e:
            result['message'] = f"Test error: {str(e)}"
            result['recommendations'] = ['Check network connectivity', 'Verify all credentials are correct']

        return result

    def _get_troubleshooting_recommendations(self, provider: str, error_message: str) -> list:
        """Get troubleshooting recommendations based on provider and error"""
        recommendations = []
        
        error_lower = error_message.lower()
        
        if self._is_amazon_ses(provider):
            recommendations.extend([
                "Verify your IAM Access Key ID starts with 'AKIA'",
                "Check that your Secret Access Key is correctly entered",
                "Ensure your IAM user has SES sending permissions",
                "Verify your email/domain is verified in SES console",
                "Check if you're still in SES sandbox mode"
            ])
            
            if 'authentication' in error_lower:
                recommendations.append("Verify IAM user has 'ses:SendRawEmail' permission")
        
        elif provider in ['gmail', 'outlook', 'yahoo']:
            recommendations.extend([
                "Enable 2-Factor Authentication on your account",
                "Generate and use an App Password instead of your regular password",
                "Check that IMAP/SMTP access is enabled in your account settings"
            ])
            
        else:
            recommendations.extend([
                "Verify SMTP server hostname and port",
                "Check if TLS/SSL is required",
                "Confirm username and password are correct"
            ])
        
        if 'connection' in error_lower or 'timeout' in error_lower:
            recommendations.extend([
                "Check your network/firewall settings",
                "Verify the SMTP port is not blocked",
                "Try using a different network connection"
            ])
        
        return recommendations

# Convenience function for direct usage (Preserved)
def validate_smtp_credentials(provider: str, email: str, username: str, password: str,
                            smtp_host: str = None, smtp_port: int = 587, use_tls: bool = True) -> Tuple[bool, str]:
    """
    Convenience function for validating SMTP credentials
    Preserves original function signature while adding SES support
    """
    validator = SMTPValidator()
    return validator.validate_provider_credentials(provider, email, username, password, smtp_host, smtp_port, use_tls)

# Export the main class and function
__all__ = ['SMTPValidator', 'validate_smtp_credentials']
