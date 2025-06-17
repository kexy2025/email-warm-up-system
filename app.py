from flask import Flask, render_template, request, jsonify, session, make_response
import os
import smtplib
import ssl
from email.mime.text import MIMEText
import secrets
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid
import logging
import socket
import hashlib
import base64
from functools import wraps
import re

app = Flask(__name__)

# FORCE PERSISTENT STORAGE - NO DATA LOSS
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'kexy-email-warmup-secret-key-2024')
database_url = os.environ.get('DATABASE_URL', 'sqlite:///email_warmup.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)
app.config['SESSION_PERMANENT'] = True

db = SQLAlchemy(app)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    auto_login = db.Column(db.Boolean, default=True)
    login_tokens = db.relationship('LoginToken', backref='user', lazy=True, cascade="all, delete-orphan")
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def generate_reset_token(self):
        self.reset_token = str(uuid.uuid4())
        self.reset_token_expires = datetime.utcnow() + timedelta(hours=24)
        db.session.commit()
        return self.reset_token
    
    def verify_reset_token(self, token):
        return self.reset_token == token and self.reset_token_expires > datetime.utcnow()
    
    def create_permanent_login(self):
        LoginToken.query.filter(LoginToken.user_id == self.id).delete()
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        login_token = LoginToken(
            user_id=self.id,
            token_hash=token_hash,
            expires_at=datetime.utcnow() + timedelta(days=365),
            created_at=datetime.utcnow(),
            user_agent=request.headers.get('User-Agent', '')[:200] if request else ''
        )
        db.session.add(login_token)
        db.session.commit()
        return raw_token
    
    def clear_all_tokens(self):
        LoginToken.query.filter(LoginToken.user_id == self.id).delete()
        db.session.commit()
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class LoginToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token_hash = db.Column(db.String(64), nullable=False, index=True, unique=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime, default=datetime.utcnow)
    user_agent = db.Column(db.String(200), nullable=True)
    
    @staticmethod
    def find_valid_token(token):
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        login_token = LoginToken.query.filter(LoginToken.token_hash == token_hash).first()
        if login_token:
            login_token.last_used = datetime.utcnow()
            login_token.expires_at = datetime.utcnow() + timedelta(days=365)
            db.session.commit()
        return login_token
    
    def is_valid(self):
        return True

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email_address = db.Column(db.String(120), nullable=False)
    smtp_host = db.Column(db.String(255), nullable=False)
    smtp_port = db.Column(db.Integer, default=587)
    smtp_username = db.Column(db.String(255), nullable=False)
    smtp_password = db.Column(db.Text, nullable=True)
    provider = db.Column(db.String(50), default='custom')
    status = db.Column(db.String(50), default='draft')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime, nullable=True)
    daily_volume = db.Column(db.Integer, default=5)
    max_volume = db.Column(db.Integer, default=100)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    emails_sent = db.Column(db.Integer, default=0)
    last_run = db.Column(db.DateTime, nullable=True)
    run_count = db.Column(db.Integer, default=0)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email_address': self.email_address,
            'smtp_host': self.smtp_host,
            'smtp_port': self.smtp_port,
            'provider': self.provider,
            'status': self.status,
            'daily_volume': self.daily_volume,
            'max_volume': self.max_volume,
            'emails_sent': self.emails_sent,
            'run_count': self.run_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'last_run': self.last_run.isoformat() if self.last_run else None
        }
# Authentication Functions
def get_current_user():
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.is_active:
            return user
    
    token = request.cookies.get('permanent_login')
    if token:
        login_token = LoginToken.find_valid_token(token)
        if login_token:
            user = User.query.get(login_token.user_id)
            if user and user.is_active:
                session.permanent = True
                session['user_id'] = user.id
                session['username'] = user.username
                session['email'] = user.email
                session['auto_logged_in'] = True
                return user
    
    if 'last_user_email' in session:
        user = User.query.filter_by(email=session['last_user_email']).first()
        if user and user.is_active and user.auto_login:
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['email'] = user.email
            return user
    
    return None

def force_user_login(user):
    try:
        user.last_login = datetime.utcnow()
        user.auto_login = True
        db.session.commit()
        
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        session['email'] = user.email
        session['last_user_email'] = user.email
        session['login_time'] = datetime.utcnow().isoformat()
        
        response_data = {
            'success': True,
            'message': f'Welcome back, {user.username}! (Persistent login active)',
            'user': user.to_dict()
        }
        
        response = make_response(jsonify(response_data))
        
        permanent_token = user.create_permanent_login()
        response.set_cookie(
            'permanent_login',
            permanent_token,
            max_age=365*24*60*60,
            httponly=True,
            secure=False,
            samesite='Lax'
        )
        
        response.set_cookie(
            'user_backup',
            user.email,
            max_age=365*24*60*60,
            httponly=False,
            secure=False
        )
        
        logger.info(f"BULLETPROOF login completed for: {user.username}")
        return response
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Login failed'})

def force_user_logout():
    user = get_current_user()
    if user:
        user.auto_login = False
        user.clear_all_tokens()
        db.session.commit()
    
    session.clear()
    response = make_response(jsonify({'success': True, 'message': 'Logged out successfully'}))
    response.set_cookie('permanent_login', '', expires=0)
    response.set_cookie('user_backup', '', expires=0)
    return response

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function
# FIXED SMTP PROVIDERS - INCLUDING AMAZON SES
SMTP_PROVIDERS = {
    'gmail': {
        'smtp_host': 'smtp.gmail.com',
        'smtp_port': 587,
        'requires_app_password': True,
        'instructions': 'Use Gmail App Password (not regular password)',
        'name': 'Gmail'
    },
    'outlook': {
        'smtp_host': 'smtp-mail.outlook.com', 
        'smtp_port': 587,
        'requires_app_password': False,
        'instructions': 'Use regular Outlook password',
        'name': 'Outlook/Hotmail'
    },
    'yahoo': {
        'smtp_host': 'smtp.mail.yahoo.com',
        'smtp_port': 587,
        'requires_app_password': True,
        'instructions': 'Use Yahoo App Password',
        'name': 'Yahoo Mail'
    },
    'amazon_ses': {
        'smtp_host': 'email-smtp.us-east-1.amazonaws.com',
        'smtp_port': 587,
        'requires_app_password': False,
        'instructions': 'Use AWS SES SMTP credentials (not IAM credentials)',
        'name': 'Amazon SES',
        'regions': {
            'us-east-1': 'email-smtp.us-east-1.amazonaws.com',
            'us-west-2': 'email-smtp.us-west-2.amazonaws.com',
            'eu-west-1': 'email-smtp.eu-west-1.amazonaws.com',
            'ap-southeast-1': 'email-smtp.ap-southeast-1.amazonaws.com',
            'us-west-1': 'email-smtp.us-west-1.amazonaws.com',
            'eu-central-1': 'email-smtp.eu-central-1.amazonaws.com'
        }
    },
    'custom': {
        'smtp_host': '',
        'smtp_port': 587,
        'requires_app_password': False,
        'instructions': 'Enter your custom SMTP settings',
        'name': 'Custom SMTP'
    }
}

# Utility Functions
def detect_email_provider(email):
    try:
        domain = email.split('@')[-1].lower()
        provider_mappings = {
            'gmail.com': 'gmail',
            'googlemail.com': 'gmail',
            'outlook.com': 'outlook',
            'hotmail.com': 'outlook',
            'live.com': 'outlook',
            'yahoo.com': 'yahoo',
            'yahoo.co.uk': 'yahoo'
        }
        return provider_mappings.get(domain, 'custom')
    except:
        return 'custom'

def clean_smtp_host(smtp_host):
    """CRITICAL FIX: Clean SMTP host to remove HTTP prefixes"""
    if not smtp_host:
        return smtp_host
    
    # Clean the host
    smtp_host = str(smtp_host).strip()
    
    # Remove protocol prefixes
    if smtp_host.startswith('http://'):
        smtp_host = smtp_host[7:]
    elif smtp_host.startswith('https://'):
        smtp_host = smtp_host[8:]
    elif smtp_host.startswith('smtp://'):
        smtp_host = smtp_host[7:]
    
    # Remove paths and trailing slashes
    smtp_host = smtp_host.split('/')[0]
    smtp_host = smtp_host.rstrip('/')
    
    logger.info(f"Cleaned SMTP host: {smtp_host}")
    return smtp_host

def is_aws_ses_smtp_username(username):
    """Check if username looks like AWS SES SMTP credentials"""
    if not username:
        return False
    return bool(re.match(r'^[A-Z0-9]{20}$', username.strip()))

def validate_smtp_comprehensive(email, password, smtp_host, smtp_port, smtp_username=None, provider='custom'):
    """BULLETPROOF SMTP validation for ALL providers"""
    if not smtp_username:
        smtp_username = email
    
    # CRITICAL: Clean the SMTP host first
    original_host = smtp_host
    smtp_host = clean_smtp_host(smtp_host)
    
    logger.info(f"🔍 SMTP Validation START")
    logger.info(f"   Provider: {provider}")
    logger.info(f"   Original Host: {original_host}")
    logger.info(f"   Cleaned Host: {smtp_host}")
    logger.info(f"   Port: {smtp_port}")
    logger.info(f"   Username: {smtp_username}")
    
    try:
        # Provider-specific validation
        if provider == 'amazon_ses':
            logger.info("🔍 AWS SES Validation...")
            
            # Check host format
            if not smtp_host.startswith('email-smtp.') or not smtp_host.endswith('.amazonaws.com'):
                return {
                    'success': False,
                    'message': f'❌ Invalid AWS SES SMTP host. Expected format: email-smtp.region.amazonaws.com, got: {smtp_host}',
                    'error_type': 'aws_ses_host_error',
                    'suggestions': [
                        'Use format: email-smtp.us-east-1.amazonaws.com',
                        'Replace us-east-1 with your AWS region',
                        'Do not include http:// or https:// prefixes'
                    ]
                }
            
            # Check username format
            if not is_aws_ses_smtp_username(smtp_username):
                return {
                    'success': False,
                    'message': f'❌ Invalid AWS SES SMTP username. Expected 20-character alphanumeric string, got: {smtp_username}',
                    'error_type': 'aws_ses_username_error',
                    'suggestions': [
                        'Use AWS SES SMTP credentials (NOT IAM credentials)',
                        'Username should be exactly 20 characters like: AKIAIOSFODNN7EXAMPLE',
                        'Get SMTP credentials from AWS SES Console > SMTP Settings > Create SMTP Credentials'
                    ]
                }
            
            logger.info("✅ AWS SES format validation passed")
        
        elif provider == 'gmail':
            if smtp_host != 'smtp.gmail.com':
                return {
                    'success': False,
                    'message': f'❌ Invalid Gmail SMTP host. Expected: smtp.gmail.com, got: {smtp_host}',
                    'error_type': 'gmail_host_error'
                }
        
        elif provider == 'yahoo':
            if smtp_host != 'smtp.mail.yahoo.com':
                return {
                    'success': False,
                    'message': f'❌ Invalid Yahoo SMTP host. Expected: smtp.mail.yahoo.com, got: {smtp_host}',
                    'error_type': 'yahoo_host_error'
                }
        
        elif provider == 'outlook':
            if smtp_host != 'smtp-mail.outlook.com':
                return {
                    'success': False,
                    'message': f'❌ Invalid Outlook SMTP host. Expected: smtp-mail.outlook.com, got: {smtp_host}',
                    'error_type': 'outlook_host_error'
                }
        
        # DNS resolution test
        logger.info(f"🔍 Testing DNS resolution for: {smtp_host}")
        try:
            resolved_ip = socket.gethostbyname(smtp_host)
            logger.info(f"✅ DNS resolution successful: {smtp_host} -> {resolved_ip}")
        except socket.gaierror as dns_error:
            logger.error(f"❌ DNS resolution failed for {smtp_host}: {dns_error}")
            return {
                'success': False,
                'message': f'❌ Cannot resolve SMTP host "{smtp_host}". Please check the hostname.',
                'error_type': 'dns_error',
                'suggestions': [
                    'Verify the SMTP hostname is correct',
                    'Check your internet connection',
                    'For AWS SES, verify the region is correct'
                ]
            }
        
        # SMTP connection test
        logger.info(f"🔌 Attempting SMTP connection to {smtp_host}:{smtp_port}")
        server = None
        
        try:
            # Choose connection method based on port
            if smtp_port == 465:
                # SSL connection
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(smtp_host, smtp_port, context=context, timeout=30)
                logger.info("🔒 Connected using SMTP_SSL (port 465)")
            else:
                # Regular SMTP with STARTTLS
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
                logger.info(f"🔌 Connected using SMTP (port {smtp_port})")
                
                # Start TLS for secure ports
                if smtp_port in [587, 25, 2587]:
                    server.starttls()
                    logger.info("🔒 STARTTLS enabled")
            
            # Test authentication
            logger.info(f"🔐 Testing authentication for: {smtp_username}")
            server.login(smtp_username, password)
            logger.info("✅ SMTP Authentication successful!")
            
            # Send test email
            logger.info("📧 Sending test email...")
            test_msg = MIMEText(f"""
✅ SMTP Configuration Validated Successfully!

Your email configuration has been tested and verified:

📧 Email: {email}
🖥️ SMTP Host: {smtp_host}
🔌 Port: {smtp_port}
👤 Username: {smtp_username}
⚙️ Provider: {provider.upper()}

🎉 Your account is now ready for email warmup campaigns!

This test email confirms that your SMTP settings are working correctly.

---
KEXY Email Warmup System
            """)
            
            test_msg['From'] = email
            test_msg['To'] = email
            test_msg['Subject'] = "✅ SMTP Validation Successful - KEXY Email Warmup"
            
            server.send_message(test_msg)
            logger.info("✅ Test email sent successfully!")
            
            server.quit()
            logger.info("🎉 SMTP validation completed successfully!")
            
            return {
                'success': True,
                'message': f'✅ SMTP validation successful! Test email sent to {email}. Check your inbox to confirm.',
                'details': f'Successfully connected to {smtp_host}:{smtp_port} using {provider}',
                'provider': provider
            }
            
        except smtplib.SMTPAuthenticationError as auth_error:
            logger.error(f"❌ SMTP Authentication failed: {auth_error}")
            
            # Provider-specific error messages
            suggestions = []
            if provider == 'amazon_ses':
                suggestions = [
                    'Verify you are using AWS SES SMTP credentials (NOT IAM access keys)',
                    'Check that your AWS SES account is not in sandbox mode',
                    'Ensure your sending email domain is verified in AWS SES',
                    'Confirm you are using the correct AWS region',
                    'Verify the SMTP password is correct (different from AWS console password)'
                ]
            elif provider == 'gmail':
                suggestions = [
                    'Use an App Password instead of your regular Gmail password',
                    'Enable 2-Factor Authentication on your Google account first',
                    'Generate App Password: Google Account > Security > App passwords',
                    'Make sure "Less secure app access" is enabled (if using regular password)'
                ]
            elif provider == 'yahoo':
                suggestions = [
                    'Use an App Password instead of your regular Yahoo password',
                    'Enable 2-Factor Authentication on your Yahoo account first',
                    'Generate App Password: Yahoo Account Security > Generate app password'
                ]
            elif provider == 'outlook':
                suggestions = [
                    'Use your regular Microsoft account password',
                    'If 2FA is enabled, create an App Password in Microsoft Account Security',
                    'Ensure your account allows SMTP access'
                ]
            else:
                suggestions = [
                    'Double-check your username and password',
                    'Verify your email provider allows SMTP access',
                    'Check if you need an app-specific password'
                ]
                
            return {
                'success': False,
                'message': f'❌ SMTP Authentication failed: {str(auth_error)}',
                'error_type': 'auth_error',
                'suggestions': suggestions
            }
            
        except smtplib.SMTPConnectError as conn_error:
            logger.error(f"❌ SMTP Connection failed: {conn_error}")
            return {
                'success': False,
                'message': f'❌ Cannot connect to SMTP server {smtp_host}:{smtp_port}. Connection error: {str(conn_error)}',
                'error_type': 'connection_error',
                'suggestions': [
                    'Verify the SMTP host and port are correct',
                    'Check your firewall/network allows SMTP connections',
                    'Try different ports: 587 (TLS), 465 (SSL), 25 (unsecured)'
                ]
            }
            
        except smtplib.SMTPServerDisconnected as disc_error:
            logger.error(f"❌ SMTP Server disconnected: {disc_error}")
            return {
                'success': False,
                'message': f'❌ SMTP server disconnected unexpectedly: {str(disc_error)}',
                'error_type': 'disconnection_error'
            }
            
        except Exception as smtp_error:
            logger.error(f"❌ SMTP Error: {smtp_error}")
            return {
                'success': False,
                'message': f'❌ SMTP Error: {str(smtp_error)}',
                'error_type': 'smtp_error'
            }
        
        finally:
            # Always close the connection
            if server:
                try:
                    server.quit()
                    logger.info("🔌 SMTP connection closed")
                except:
                    pass
        
    except Exception as general_error:
        logger.error(f"❌ General validation error: {general_error}")
        return {
            'success': False,
            'message': f'❌ Validation failed: {str(general_error)}',
            'error_type': 'general_error'
        }

def get_setup_instructions(provider):
    """Get setup instructions for each provider"""
    base_instructions = {
        'gmail': {
            'title': 'Gmail Setup Instructions',
            'steps': [
                '1. Enable 2-Factor Authentication on your Google account',
                '2. Go to Google Account settings > Security > App passwords',
                '3. Generate an App Password for "Mail"',
                '4. Use your Gmail address and the generated App Password (not your regular password)'
            ]
        },
        'outlook': {
            'title': 'Outlook Setup Instructions', 
            'steps': [
                '1. Use your regular Microsoft account email and password',
                '2. If 2FA is enabled, create an App Password in Microsoft Account Security',
                '3. Ensure your account allows SMTP access'
            ]
        },
        'yahoo': {
            'title': 'Yahoo Mail Setup Instructions',
            'steps': [
                '1. Enable 2-Factor Authentication on your Yahoo account',
                '2. Go to Yahoo Account Security settings',
                '3. Generate an App Password for "Mail" application',
                '4. Use your Yahoo email and the generated App Password'
            ]
        },
        'amazon_ses': {
            'title': 'Amazon SES Setup Instructions',
            'steps': [
                '1. Log into AWS Console and navigate to Amazon SES',
                '2. Go to Account Dashboard > SMTP Settings',
                '3. Click "Create SMTP Credentials" (NOT IAM credentials)',
                '4. Download the SMTP username and password',
                '5. Verify your domain/email in SES if in sandbox mode',
                '6. Use the SES SMTP endpoint for your region (e.g., email-smtp.us-east-1.amazonaws.com)'
            ]
        },
        'custom': {
            'title': 'Custom SMTP Setup',
            'steps': [
                '1. Get SMTP settings from your email provider',
                '2. Enter the correct SMTP host and port',
                '3. Use your email credentials or app-specific password'
            ]
        }
    }
    return base_instructions.get(provider, base_instructions['custom'])
# Routes
@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    user = get_current_user()
    if user:
        return jsonify({'authenticated': True, 'user': user.to_dict()})
    else:
        return jsonify({'authenticated': False})

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password are required'})
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            return force_user_login(user)
        else:
            return jsonify({'success': False, 'message': 'Invalid email or password'})
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'success': False, 'message': 'Login failed'})

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        if not username or not email or not password:
            return jsonify({'success': False, 'message': 'All fields are required'})
        
        if len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'})
        
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already registered'})
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already taken'})
        
        user = User(username=username, email=email)
        user.set_password(password)
        user.auto_login = True
        
        db.session.add(user)
        db.session.commit()
        
        return force_user_login(user)
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Registration failed'})

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json()
        email = data.get('email', '').lower().strip()
        
        if not email:
            return jsonify({'success': False, 'message': 'Email is required'})
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            reset_token = user.generate_reset_token()
            return jsonify({
                'success': True,
                'message': 'Password reset instructions sent to your email',
                'reset_token': reset_token,
                'reset_url': f'/?token={reset_token}'
            })
        else:
            return jsonify({
                'success': True,
                'message': 'If that email exists, password reset instructions have been sent'
            })
    except Exception as e:
        return jsonify({'success': False, 'message': 'Request failed'})

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        token = data.get('token', '')
        new_password = data.get('password', '')
        
        if not token or not new_password:
            return jsonify({'success': False, 'message': 'Token and new password are required'})
        
        if len(new_password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'})
        
        user = User.query.filter_by(reset_token=token).first()
        
        if user and user.verify_reset_token(token):
            user.set_password(new_password)
            user.reset_token = None
            user.reset_token_expires = None
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Password reset successfully! You can now login with your new password.'
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid or expired reset token'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Reset failed'})

@app.route('/api/logout', methods=['POST'])
def logout():
    return force_user_logout()

@app.route('/api/detect-provider', methods=['POST'])
def detect_provider():
    try:
        data = request.get_json()
        email = data.get('email', '')
        
        provider = detect_email_provider(email)
        config = SMTP_PROVIDERS.get(provider, SMTP_PROVIDERS['custom'])
        
        # IMPORTANT: Return ALL providers for frontend dropdown
        return jsonify({
            'provider': provider,
            'config': config,
            'all_providers': SMTP_PROVIDERS,
            'setup_instructions': get_setup_instructions(provider)
        })
    except Exception as e:
        return jsonify({'error': 'Provider detection failed'})

@app.route('/api/test-smtp', methods=['POST'])
def test_smtp():
    try:
        data = request.get_json()
        
        email = data.get('email', '')
        password = data.get('password', '')
        smtp_host = data.get('smtp_host', '')
        smtp_port = int(data.get('smtp_port', 587))
        smtp_username = data.get('smtp_username', email)
        provider = data.get('provider', 'custom')
        
        if not all([email, password, smtp_host]):
            return jsonify({
                'success': False,
                'message': 'Email, SMTP host, and password are required'
            })
        
        result = validate_smtp_comprehensive(email, password, smtp_host, smtp_port, smtp_username, provider)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"SMTP test error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'SMTP test failed: {str(e)}'
        })

@app.route('/api/dashboard/stats')
@require_auth
def dashboard_stats():
    try:
        user = get_current_user()
        campaigns = Campaign.query.filter_by(user_id=user.id).all()
        
        total_emails = sum(c.emails_sent for c in campaigns)
        total_runs = sum(c.run_count for c in campaigns)
        
        stats = {
            'active_campaigns': len([c for c in campaigns if c.status == 'active']),
            'total_campaigns': len(campaigns),
            'emails_sent_today': total_emails,
            'total_runs': total_runs,
            'avg_reputation_score': 85.5
        }
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': 'Failed to load stats'})

@app.route('/api/campaigns', methods=['GET', 'POST'])
@require_auth
def campaigns_api():
    user = get_current_user()
    
    try:
        if request.method == 'POST':
            data = request.get_json()
            
            required_fields = ['name', 'email', 'smtp_host', 'smtp_password']
            for field in required_fields:
                if not data.get(field):
                    return jsonify({'success': False, 'message': f'{field} is required'})
            
            campaign = Campaign(
                name=data.get('name'),
                email_address=data.get('email'),
                smtp_host=clean_smtp_host(data.get('smtp_host')),
                smtp_port=data.get('smtp_port', 587),
                smtp_username=data.get('smtp_username', data.get('email')),
                smtp_password=data.get('smtp_password'),
                provider=data.get('provider', 'custom'),
                user_id=user.id
            )
            
            db.session.add(campaign)
            db.session.commit()
            
            logger.info(f"Campaign saved: {campaign.name} for user: {user.username}")
            
            return jsonify({
                'success': True, 
                'message': 'Campaign created successfully', 
                'campaign': campaign.to_dict()
            })
        
        else:
            campaigns = Campaign.query.filter_by(user_id=user.id).all()
            return jsonify([c.to_dict() for c in campaigns])
            
    except Exception as e:
        logger.error(f"Campaign error: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Campaign operation failed'})

def cleanup_expired_tokens():
    try:
        expired_count = LoginToken.query.filter(
            LoginToken.expires_at < datetime.utcnow()
        ).delete()
        db.session.commit()
        if expired_count > 0:
            logger.info(f"Cleaned up {expired_count} expired login tokens")
    except Exception as e:
        logger.error(f"Token cleanup error: {e}")
        db.session.rollback()

with app.app_context():
    db.create_all()
    cleanup_expired_tokens()
    
    if not User.query.filter_by(email='demo@example.com').first():
        demo_user = User(username='demo', email='demo@example.com')
        demo_user.set_password('demo123')
        demo_user.auto_login = True
        db.session.add(demo_user)
        db.session.commit()
        logger.info("Demo user created: demo@example.com / demo123")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)

