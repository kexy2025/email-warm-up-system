from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import os
import json
import smtplib
import ssl
import imaplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import base64
from urllib.parse import urlencode
import secrets
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid
from cryptography.fernet import Fernet
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import asyncio
import aiosmtplib
from email.mime.text import MIMEText as AsyncMIMEText
import threading
from concurrent.futures import ThreadPoolExecutor
import logging

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///email_warmup.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 120,
    'pool_pre_ping': True
}

# Security
csrf = CSRFProtect(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Encryption
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key().decode())
cipher_suite = Fernet(ENCRYPTION_KEY.encode())

# Initialize database
db = SQLAlchemy(app)

# Logging
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
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    campaigns = db.relationship('Campaign', backref='user', lazy=True, cascade='all, delete-orphan')
    oauth_tokens = db.relationship('OAuthToken', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def generate_reset_token(self):
        self.reset_token = str(uuid.uuid4())
        self.reset_token_expires = datetime.utcnow() + timedelta(hours=24)
        db.session.commit()
        return self.reset_token
    
    def verify_reset_token(self, token):
        if self.reset_token == token and self.reset_token_expires > datetime.utcnow():
            return True
        return False
    
    def is_locked(self):
        return self.locked_until and self.locked_until > datetime.utcnow()
    
    def lock_account(self):
        self.locked_until = datetime.utcnow() + timedelta(minutes=30)
        db.session.commit()
    
    def unlock_account(self):
        self.failed_login_attempts = 0
        self.locked_until = None
        db.session.commit()
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email_address = db.Column(db.String(120), nullable=False)
    smtp_host = db.Column(db.String(255), nullable=False)
    smtp_port = db.Column(db.Integer, default=587)
    smtp_username = db.Column(db.String(255), nullable=False)
    smtp_password_encrypted = db.Column(db.Text, nullable=True)
    provider = db.Column(db.String(50), default='custom')
    status = db.Column(db.String(50), default='draft')
    oauth_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime, nullable=True)
    paused_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    daily_volume = db.Column(db.Integer, default=5)
    max_volume = db.Column(db.Integer, default=100)
    
    # Foreign Keys
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    email_logs = db.relationship('EmailLog', backref='campaign', lazy=True, cascade='all, delete-orphan')
    campaign_metrics = db.relationship('CampaignMetrics', backref='campaign', lazy=True, cascade='all, delete-orphan')
    
    def encrypt_password(self, password):
        if password:
            self.smtp_password_encrypted = cipher_suite.encrypt(password.encode()).decode()
    
    def decrypt_password(self):
        if self.smtp_password_encrypted:
            return cipher_suite.decrypt(self.smtp_password_encrypted.encode()).decode()
        return None
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email_address': self.email_address,
            'smtp_host': self.smtp_host,
            'smtp_port': self.smtp_port,
            'provider': self.provider,
            'status': self.status,
            'oauth_enabled': self.oauth_enabled,
            'daily_volume': self.daily_volume,
            'max_volume': self.max_volume,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None
        }

class EmailLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_email = db.Column(db.String(120), nullable=False)
    recipient_email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(500), nullable=True)
    status = db.Column(db.String(50), default='sent')
    smtp_response = db.Column(db.Text, nullable=True)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    bounce_reason = db.Column(db.String(500), nullable=True)
    
    # Foreign Keys
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'sender_email': self.sender_email,
            'recipient_email': self.recipient_email,
            'subject': self.subject,
            'status': self.status,
            'sent_at': self.sent_at.isoformat() if self.sent_at else None
        }

class CampaignMetrics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    emails_sent = db.Column(db.Integer, default=0)
    emails_delivered = db.Column(db.Integer, default=0)
    emails_bounced = db.Column(db.Integer, default=0)
    reputation_score = db.Column(db.Float, default=0.0)
    
    # Foreign Keys
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'date': self.date.isoformat() if self.date else None,
            'emails_sent': self.emails_sent,
            'emails_delivered': self.emails_delivered,
            'emails_bounced': self.emails_bounced,
            'reputation_score': self.reputation_score
        }

class OAuthToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(50), nullable=False)
    access_token = db.Column(db.Text, nullable=False)
    refresh_token = db.Column(db.Text, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Foreign Keys
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# SMTP provider configurations
SMTP_PROVIDERS = {
    'gmail': {
        'smtp_host': 'smtp.gmail.com',
        'smtp_port': 587,
        'oauth_enabled': True,
        'requires_app_password': True
    },
    'outlook': {
        'smtp_host': 'smtp-mail.outlook.com',
        'smtp_port': 587,
        'oauth_enabled': True,
        'requires_app_password': False
    },
    'yahoo': {
        'smtp_host': 'smtp.mail.yahoo.com',
        'smtp_port': 587,
        'oauth_enabled': True,
        'requires_app_password': True
    },
    'aws_ses': {
        'smtp_host': 'email-smtp.{region}.amazonaws.com',
        'smtp_port': 587,
        'oauth_enabled': False
    },
    'custom': {
        'smtp_host': '',
        'smtp_port': 587,
        'oauth_enabled': False
    }
}

# Utility Functions
def detect_email_provider(email):
    """Auto-detect email provider from email address"""
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

def validate_smtp_async(email, password, smtp_host, smtp_port, smtp_username=None, provider='custom'):
    """Async SMTP validation to prevent blocking"""
    def _validate():
        try:
            if not smtp_username:
                smtp_username = email
            
            # Test SMTP connection
            if smtp_port == 465:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(smtp_host, smtp_port, context=context)
            else:
                server = smtplib.SMTP(smtp_host, smtp_port)
                server.starttls()
            
            # Authenticate
            server.login(smtp_username, password)
            
            # Send test email
            test_msg = MIMEText(f"""
SMTP Configuration Validated Successfully!

Your email account ({email}) is properly configured and ready for email warmup campaigns.

Test Details:
- SMTP Server: {smtp_host}:{smtp_port}
- Username: {smtp_username}
- Provider: {provider.upper()}

You can now proceed with creating your email warmup campaign.

---
Email Warmup System
            """)
            
            test_msg['From'] = email
            test_msg['To'] = email
            test_msg['Subject'] = "✅ SMTP Validation Successful - Email Warmup System"
            
            server.send_message(test_msg)
            server.quit()
            
            return {
                'success': True,
                'message': f'✅ SMTP validation successful! Test email sent to {email}',
                'details': f'Connected to {smtp_host}:{smtp_port}'
            }
            
        except smtplib.SMTPAuthenticationError as e:
            return {
                'success': False,
                'message': f'❌ SMTP Authentication failed: {str(e)}. Check username and password.',
                'error_type': 'auth_error'
            }
        except smtplib.SMTPConnectError as e:
            return {
                'success': False,
                'message': f'❌ Could not connect to SMTP server {smtp_host}:{smtp_port}. Error: {str(e)}',
                'error_type': 'connection_error'
            }
        except Exception as e:
            return {
                'success': False,
                'message': f'❌ SMTP test failed: {str(e)}',
                'error_type': 'general_error'
            }
    
    # Run validation in thread pool to avoid blocking
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_validate)
        return future.result(timeout=30)  # 30 second timeout

# Routes
@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    try:
        data = request.get_json()
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password are required'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
        
        if user.is_locked():
            return jsonify({'success': False, 'message': 'Account temporarily locked due to too many failed attempts'}), 423
        
        if user.check_password(password):
            # Successful login
            user.last_login = datetime.utcnow()
            user.unlock_account()  # Reset failed attempts
            db.session.commit()
            
            # Set session
            session['user_id'] = user.id
            session['username'] = user.username
            session['email'] = user.email
            session['csrf_token'] = secrets.token_hex(16)
            
            logger.info(f"Successful login for user: {email}")
            
            return jsonify({
                'success': True, 
                'message': f'Welcome back, {user.username}!', 
                'user': user.to_dict(),
                'csrf_token': session['csrf_token']
            })
        else:
            # Failed login
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.lock_account()
                logger.warning(f"Account locked for user: {email}")
            db.session.commit()
            
            logger.warning(f"Failed login attempt for user: {email}")
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred during login'}), 500

@app.route('/api/register', methods=['POST'])
@limiter.limit("3 per minute")
def register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        # Validation
        if not username or not email or not password:
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
        
        if len(username) < 3:
            return jsonify({'success': False, 'message': 'Username must be at least 3 characters'}), 400
        
        # Check if user exists
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already registered'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already taken'}), 400
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # Set session
        session['user_id'] = user.id
        session['username'] = user.username
        session['email'] = user.email
        session['csrf_token'] = secrets.token_hex(16)
        
        logger.info(f"New user registered: {email}")
        
        return jsonify({
            'success': True, 
            'message': f'Account created successfully! Welcome, {username}!', 
            'user': user.to_dict(),
            'csrf_token': session['csrf_token']
        })
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred during registration'}), 500

@app.route('/api/forgot-password', methods=['POST'])
@limiter.limit("3 per hour")
def forgot_password():
    try:
        data = request.get_json()
        email = data.get('email', '').lower().strip()
        
        if not email:
            return jsonify({'success': False, 'message': 'Email is required'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate reset token
            reset_token = user.generate_reset_token()
            
            # In production, send email here
            # For demo, we'll just log it
            logger.info(f"Password reset requested for: {email}, token: {reset_token}")
            
            return jsonify({
                'success': True,
                'message': 'If that email exists, password reset instructions have been sent',
                # Remove these in production:
                'demo_reset_url': f'/reset-password?token={reset_token}',
                'demo_note': 'In production, this would be sent via email'
            })
        else:
            # Don't reveal if email exists
            return jsonify({
                'success': True,
                'message': 'If that email exists, password reset instructions have been sent'
            })
            
    except Exception as e:
        logger.error(f"Forgot password error: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred'}), 500

@app.route('/api/reset-password', methods=['POST'])
@limiter.limit("5 per hour")
def reset_password():
    try:
        data = request.get_json()
        token = data.get('token', '')
        new_password = data.get('password', '')
        
        if not token or not new_password:
            return jsonify({'success': False, 'message': 'Token and new password are required'}), 400
        
        if len(new_password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
        
        user = User.query.filter_by(reset_token=token).first()
        
        if user and user.verify_reset_token(token):
            user.set_password(new_password)
            user.reset_token = None
            user.reset_token_expires = None
            user.unlock_account()  # Clear any account locks
            db.session.commit()
            
            logger.info(f"Password reset successful for user: {user.email}")
            
            return jsonify({
                'success': True,
                'message': 'Password reset successfully! You can now login with your new password.'
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid or expired reset token'}), 400
            
    except Exception as e:
        logger.error(f"Reset password error: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/detect-provider', methods=['POST'])
def detect_provider():
    try:
        data = request.get_json()
        email = data.get('email', '')
        
        provider = detect_email_provider(email)
        config = SMTP_PROVIDERS.get(provider, SMTP_PROVIDERS['custom'])
        
        return jsonify({
            'provider': provider,
            'config': config,
            'setup_instructions': get_setup_instructions(provider)
        })
    except Exception as e:
        logger.error(f"Provider detection error: {str(e)}")
        return jsonify({'error': 'Provider detection failed'}), 500

def get_setup_instructions(provider):
    instructions = {
        'gmail': {
            'title': 'Gmail Setup Instructions',
            'steps': [
                '1. Enable 2-Factor Authentication on your Google account',
                '2. Go to Google Account settings > Security > App passwords',
                '3. Generate an App Password for "Mail"',
                '4. Use your email and the generated App Password'
            ]
        },
        'outlook': {
            'title': 'Outlook Setup Instructions',
            'steps': [
                '1. Use your regular email and password',
                '2. If 2FA is enabled, create an App Password'
            ]
        },
        'yahoo': {
            'title': 'Yahoo Mail Setup Instructions',
            'steps': [
                '1. Enable 2-Factor Authentication',
                '2. Generate app password for Mail',
                '3. Use email and generated password'
            ]
        },
        'aws_ses': {
            'title': 'AWS SES Setup Instructions',
            'steps': [
                '1. Get SMTP credentials from AWS SES console',
                '2. Use SMTP username and password from AWS'
            ]
        }
    }
    return instructions.get(provider, {'title': 'Custom SMTP', 'steps': ['Configure SMTP settings manually']})

@app.route('/api/test-smtp', methods=['POST'])
@limiter.limit("10 per hour")
def test_smtp():
    try:
        data = request.get_json()
        
        email = data.get('email', '')
        password = data.get('password', '')
        smtp_host = data.get('smtp_host', '')
        smtp_port = int(data.get('smtp_port', 587))
        smtp_username = data.get('smtp_username', email)
        provider = data.get('provider', 'custom')
        
        if not email or not smtp_host or not password:
            return jsonify({
                'success': False,
                'message': 'Email, SMTP host, and password are required'
            })
        
        # Run validation asynchronously
        result = validate_smtp_async(email, password, smtp_host, smtp_port, smtp_username, provider)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"SMTP test error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'SMTP test failed: {str(e)}'
        }), 500

@app.route('/api/dashboard/stats')
def dashboard_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        user_id = session['user_id']
        campaigns = Campaign.query.filter_by(user_id=user_id).all()
        
        # Calculate metrics
        active_campaigns = len([c for c in campaigns if c.status == 'active'])
        total_campaigns = len(campaigns)
        
        # Get email logs for today
        today = datetime.utcnow().date()
        emails_sent_today = db.session.query(EmailLog).join(Campaign).filter(
            Campaign.user_id == user_id,
            db.func.date(EmailLog.sent_at) == today
        ).count()
        
        # Calculate average reputation score
        recent_metrics = db.session.query(CampaignMetrics).join(Campaign).filter(
            Campaign.user_id == user_id,
            CampaignMetrics.date >= today - timedelta(days=7)
        ).all()
        
        avg_reputation = sum(m.reputation_score for m in recent_metrics) / len(recent_metrics) if recent_metrics else 0
        
        stats = {
            'active_campaigns': active_campaigns,
            'total_campaigns': total_campaigns,
            'emails_sent_today': emails_sent_today,
            'avg_reputation_score': round(avg_reputation, 1)
        }
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Dashboard stats error: {str(e)}")
        return jsonify({'error': 'Failed to load dashboard stats'}), 500

@app.route('/api/campaigns', methods=['GET', 'POST'])
def campaigns_api():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            # Validation
            required_fields = ['name', 'email', 'smtp_host', 'smtp_password']
            for field in required_fields:
                if not data.get(field):
                    return jsonify({'success': False, 'message': f'{field} is required'}), 400
            
            campaign = Campaign(
                name=data.get('name'),
                email_address=data.get('email'),
                smtp_host=data.get('smtp_host'),
                smtp_port=data.get('smtp_port', 587),
                smtp_username=data.get('smtp_username'),
                provider=data.get('provider'),
                daily_volume=data.get('daily_volume', 5),
                max_volume=data.get('max_volume', 100),
                user_id=user_id
            )
            
            # Encrypt password
            campaign.encrypt_password(data.get('smtp_password'))
            
            db.session.add(campaign)
            db.session.commit()
            
            logger.info(f"Campaign created: {campaign.name} for user {user_id}")
            
            return jsonify({
                'success': True, 
                'message': 'Campaign created successfully', 
                'campaign': campaign.to_dict()
            })
            
        except Exception as e:
            logger.error(f"Campaign creation error: {str(e)}")
            db.session.rollback()
            return jsonify({'success': False, 'message': 'Failed to create campaign'}), 500
    
    else:
        try:
            campaigns = Campaign.query.filter_by(user_id=user_id).all()
            return jsonify([c.to_dict() for c in campaigns])
        except Exception as e:
            logger.error(f"Campaign fetch error: {str(e)}")
            return jsonify({'error': 'Failed to fetch campaigns'}), 500

@app.route('/api/campaigns/<int:campaign_id>/start', methods=['POST'])
def start_campaign(campaign_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        campaign = Campaign.query.filter_by(id=campaign_id, user_id=session['user_id']).first()
        
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404
        
        if campaign.status == 'active':
            return jsonify({'success': False, 'message': 'Campaign is already active'}), 400
        
        campaign.status = 'active'
        campaign.started_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Campaign started: {campaign.name}")
        
        return jsonify({'success': True, 'message': 'Campaign started successfully'})
        
    except Exception as e:
        logger.error(f"Start campaign error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to start campaign'}), 500

@app.route('/api/campaigns/<int:campaign_id>/pause', methods=['POST'])
def pause_campaign(campaign_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        campaign = Campaign.query.filter_by(id=campaign_id, user_id=session['user_id']).first()
        
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404
        
        campaign.status = 'paused'
        campaign.paused_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Campaign paused: {campaign.name}")
        
        return jsonify({'success': True, 'message': 'Campaign paused successfully'})
        
    except Exception as e:
        logger.error(f"Pause campaign error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to pause campaign'}), 500

@app.route('/api/campaigns/<int:campaign_id>/stop', methods=['POST'])
def stop_campaign(campaign_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        campaign = Campaign.query.filter_by(id=campaign_id, user_id=session['user_id']).first()
        
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404
        
        campaign.status = 'stopped'
        campaign.completed_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Campaign stopped: {campaign.name}")
        
        return jsonify({'
