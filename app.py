#!/usr/bin/env python3
"""
KEXY Email Warmup System - Complete Application
Includes authentication, database persistence, and Amazon SES support
FIXED: Removed login requirements from API routes for Railway deployment
"""

import os
import logging
from datetime import datetime, timedelta
import json
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import hashlib
from functools import wraps

# Flask and extensions
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import requests

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///warmup.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

# Handle PostgreSQL URL format for Railway
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgresql://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgresql://', 'postgresql+psycopg2://', 1)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
CORS(app)

# Encryption key for sensitive data
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key()).encode() if isinstance(os.environ.get('ENCRYPTION_KEY', Fernet.generate_key()), str) else os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
cipher_suite = Fernet(ENCRYPTION_KEY)

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# SMTP Provider Configurations (ENHANCED with Amazon SES)
SMTP_PROVIDERS = {
    'gmail': {
        'host': 'smtp.gmail.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'help_text': 'For Gmail: Enable 2-Factor Authentication and generate an App Password'
    },
    'outlook': {
        'host': 'smtp-mail.outlook.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'help_text': 'For Outlook: Enable 2-Factor Authentication and generate an App Password'
    },
    'yahoo': {
        'host': 'smtp.mail.yahoo.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'help_text': 'For Yahoo: Enable 2-Factor Authentication and generate an App Password'
    },
    # ENHANCED: Amazon SES regional configurations
    'amazon_ses_us_east_1': {
        'host': 'email-smtp.us-east-1.amazonaws.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'region': 'us-east-1',
        'service': 'ses',
        'help_text': 'Amazon SES (US East 1): Use IAM Access Key ID as username and Secret Access Key as password'
    },
    'amazon_ses_us_west_2': {
        'host': 'email-smtp.us-west-2.amazonaws.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'region': 'us-west-2',
        'service': 'ses',
        'help_text': 'Amazon SES (US West 2): Use IAM Access Key ID as username and Secret Access Key as password'
    },
    'amazon_ses_us_west_1': {
        'host': 'email-smtp.us-west-1.amazonaws.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'region': 'us-west-1',
        'service': 'ses',
        'help_text': 'Amazon SES (US West 1): Use IAM Access Key ID as username and Secret Access Key as password'
    },
    'amazon_ses_eu_west_1': {
        'host': 'email-smtp.eu-west-1.amazonaws.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'region': 'eu-west-1',
        'service': 'ses',
        'help_text': 'Amazon SES (EU West 1): Use IAM Access Key ID as username and Secret Access Key as password'
    },
    'amazon_ses_eu_central_1': {
        'host': 'email-smtp.eu-central-1.amazonaws.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'region': 'eu-central-1',
        'service': 'ses',
        'help_text': 'Amazon SES (EU Central 1): Use IAM Access Key ID as username and Secret Access Key as password'
    },
    'amazon_ses_ap_southeast_1': {
        'host': 'email-smtp.ap-southeast-1.amazonaws.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'region': 'ap-southeast-1',
        'service': 'ses',
        'help_text': 'Amazon SES (Asia Pacific - Singapore): Use IAM Access Key ID as username and Secret Access Key as password'
    },
    'amazon_ses_ap_southeast_2': {
        'host': 'email-smtp.ap-southeast-2.amazonaws.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'region': 'ap-southeast-2',
        'service': 'ses',
        'help_text': 'Amazon SES (Asia Pacific - Sydney): Use IAM Access Key ID as username and Secret Access Key as password'
    },
    'amazon_ses_ap_northeast_1': {
        'host': 'email-smtp.ap-northeast-1.amazonaws.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'region': 'ap-northeast-1',
        'service': 'ses',
        'help_text': 'Amazon SES (Asia Pacific - Tokyo): Use IAM Access Key ID as username and Secret Access Key as password'
    },
    'amazon_ses_ca_central_1': {
        'host': 'email-smtp.ca-central-1.amazonaws.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'region': 'ca-central-1',
        'service': 'ses',
        'help_text': 'Amazon SES (Canada Central): Use IAM Access Key ID as username and Secret Access Key as password'
    },
    'custom_ses': {
        'host': '',  # To be filled by user
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'service': 'ses',
        'help_text': 'Amazon SES (Custom Region): Enter your region-specific SES SMTP endpoint'
    },
    'custom_smtp': {
        'host': '',  # To be filled by user
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'help_text': 'Custom SMTP: Enter your server details manually'
    }
}

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    campaigns = db.relationship('Campaign', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active
        }

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    provider = db.Column(db.String(50), nullable=False)
    smtp_host = db.Column(db.String(255))
    smtp_port = db.Column(db.Integer, default=587)
    smtp_username = db.Column(db.String(255))
    smtp_password_encrypted = db.Column(db.Text)  # Encrypted password
    use_tls = db.Column(db.Boolean, default=True)
    industry = db.Column(db.String(100))
    daily_volume = db.Column(db.Integer, default=10)
    warmup_days = db.Column(db.Integer, default=30)
    status = db.Column(db.String(20), default='created')  # created, active, paused, completed
    progress = db.Column(db.Integer, default=0)
    emails_sent = db.Column(db.Integer, default=0)
    success_rate = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def encrypt_password(self, password):
        """Encrypt the SMTP password"""
        if password:
            self.smtp_password_encrypted = cipher_suite.encrypt(password.encode()).decode()

    def decrypt_password(self):
        """Decrypt the SMTP password"""
        if self.smtp_password_encrypted:
            return cipher_suite.decrypt(self.smtp_password_encrypted.encode()).decode()
        return None

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'provider': self.provider,
            'smtp_host': self.smtp_host,
            'smtp_port': self.smtp_port,
            'smtp_username': self.smtp_username,
            'use_tls': self.use_tls,
            'industry': self.industry,
            'daily_volume': self.daily_volume,
            'warmup_days': self.warmup_days,
            'status': self.status,
            'progress': self.progress,
            'emails_sent': self.emails_sent,
            'success_rate': self.success_rate,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class EmailLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    recipient = db.Column(db.String(255))
    subject = db.Column(db.String(500))
    status = db.Column(db.String(20))  # sent, failed, bounced
    error_message = db.Column(db.Text)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    campaign = db.relationship('Campaign', backref='email_logs')

# Login manager user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Utility Functions
def validate_smtp_connection(provider, email, username, password, smtp_host=None, smtp_port=587, use_tls=True):
    """Enhanced SMTP validation with Amazon SES support"""
    try:
        # Get provider configuration
        if provider in SMTP_PROVIDERS:
            config = SMTP_PROVIDERS[provider]
            host = smtp_host if smtp_host else config['host']
            port = smtp_port if smtp_port else config['port']
            tls = use_tls if use_tls is not None else config['use_tls']
        else:
            return False, f"Unsupported provider: {provider}"

        # Validate custom providers
        if provider in ['custom_smtp', 'custom_ses'] and not smtp_host:
            return False, "SMTP host is required for custom providers"

        # Amazon SES specific validation
        if 'amazon_ses' in provider or provider == 'custom_ses':
            # Validate SES credentials format
            if not username or not username.startswith('AKIA'):
                return False, "Amazon SES username should be an IAM Access Key ID starting with 'AKIA'"
            
            if not password or len(password) < 20:
                return False, "Amazon SES password should be a Secret Access Key (at least 20 characters)"

        # Test SMTP connection
        logger.info(f"Testing SMTP connection to {host}:{port}")
        
        if tls:
            server = smtplib.SMTP(host, port)
            server.starttls()
        else:
            server = smtplib.SMTP(host, port)

        # Authenticate
        server.login(username, password)
        server.quit()
        
        logger.info("SMTP connection test successful")
        return True, "Connection successful"

    except smtplib.SMTPAuthenticationError as e:
        error_msg = f"Authentication failed: {str(e)}"
        if 'amazon_ses' in provider:
            error_msg += " Please verify your IAM Access Key ID and Secret Access Key."
        return False, error_msg
    except smtplib.SMTPConnectError as e:
        return False, f"Connection failed: {str(e)}"
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {str(e)}"
    except Exception as e:
        logger.error(f"SMTP validation error: {str(e)}")
        return False, f"Unexpected error: {str(e)}"

def create_default_user():
    """Create default admin user if no users exist"""
    if User.query.count() == 0:
        admin = User(
            username='admin',
            email='admin@example.com'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        logger.info("Default admin user created")

# Routes
@app.route('/')
def index():
    # FIXED: Auto-login for testing purposes
    admin_user = User.query.first()
    if admin_user and not current_user.is_authenticated:
        login_user(admin_user)
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        password = data.get('password')
        remember = data.get('remember', False)

        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            if request.is_json:
                return jsonify({'success': True, 'message': 'Login successful'})
            return redirect(url_for('index'))
        else:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
            flash('Invalid credentials')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        # Check if user exists
        if User.query.filter_by(username=username).first():
            if request.is_json:
                return jsonify({'success': False, 'message': 'Username already exists'}), 400
            flash('Username already exists')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            if request.is_json:
                return jsonify({'success': False, 'message': 'Email already registered'}), 400
            flash('Email already registered')
            return render_template('register.html')

        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        if request.is_json:
            return jsonify({'success': True, 'message': 'Registration successful'})
        flash('Registration successful')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# API Routes - FIXED: Removed @login_required decorators
@app.route('/api/validate-smtp', methods=['POST'])
def validate_smtp():
    try:
        data = request.get_json()
        provider = data.get('provider')
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')
        smtp_host = data.get('smtp_host')
        smtp_port = data.get('smtp_port', 587)
        use_tls = data.get('use_tls', True)

        if not all([provider, email, username, password]):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400

        success, message = validate_smtp_connection(
            provider, email, username, password, smtp_host, smtp_port, use_tls
        )

        return jsonify({'success': success, 'message': message})

    except Exception as e:
        logger.error(f"SMTP validation error: {str(e)}")
        return jsonify({'success': False, 'message': 'Validation failed'}), 500

@app.route('/api/campaigns', methods=['GET', 'POST'])
def campaigns():
    if request.method == 'GET':
        # FIXED: Get all campaigns or default to admin user's campaigns
        try:
            if current_user.is_authenticated:
                user_campaigns = Campaign.query.filter_by(user_id=current_user.id).all()
            else:
                # Get admin user's campaigns as default
                admin_user = User.query.first()
                if admin_user:
                    user_campaigns = Campaign.query.filter_by(user_id=admin_user.id).all()
                else:
                    user_campaigns = []
            return jsonify([campaign.to_dict() for campaign in user_campaigns])
        except Exception as e:
            logger.error(f"Campaigns GET error: {str(e)}")
            return jsonify([])

    elif request.method == 'POST':
        try:
            data = request.get_json()
            
            # Validate required fields
            required_fields = ['name', 'email', 'provider', 'username', 'password', 'industry']
            if not all(field in data for field in required_fields):
                return jsonify({'success': False, 'message': 'Missing required fields'}), 400

            # Get provider configuration
            provider = data['provider']
            if provider not in SMTP_PROVIDERS and provider not in ['custom_smtp', 'custom_ses']:
                return jsonify({'success': False, 'message': 'Invalid provider'}), 400

            # Validate SMTP connection first
            success, message = validate_smtp_connection(
                provider,
                data['email'],
                data['username'],
                data['password'],
                data.get('smtp_host'),
                data.get('smtp_port', 587),
                data.get('use_tls', True)
            )

            if not success:
                return jsonify({'success': False, 'message': f'SMTP validation failed: {message}'}), 400

            # FIXED: Get user_id properly
            if current_user.is_authenticated:
                user_id = current_user.id
            else:
                # Use admin user as default
                admin_user = User.query.first()
                user_id = admin_user.id if admin_user else 1

            # Create campaign
            campaign = Campaign(
                name=data['name'],
                email=data['email'],
                provider=provider,
                smtp_host=data.get('smtp_host') or SMTP_PROVIDERS.get(provider, {}).get('host'),
                smtp_port=data.get('smtp_port', 587),
                smtp_username=data['username'],
                use_tls=data.get('use_tls', True),
                industry=data['industry'],
                daily_volume=data.get('daily_volume', 10),
                warmup_days=data.get('warmup_days', 30),
                user_id=user_id
            )

            # Encrypt password
            campaign.encrypt_password(data['password'])

            db.session.add(campaign)
            db.session.commit()

            logger.info(f"Campaign created: {campaign.name}")
            return jsonify({'success': True, 'message': 'Campaign created successfully', 'campaign': campaign.to_dict()})

        except Exception as e:
            logger.error(f"Campaign creation error: {str(e)}")
            db.session.rollback()
            return jsonify({'success': False, 'message': 'Failed to create campaign'}), 500

@app.route('/api/campaigns/', methods=['GET', 'PUT', 'DELETE'])
def campaign_detail(campaign_id):
    # FIXED: Handle campaign access without strict user filtering
    if current_user.is_authenticated:
        campaign = Campaign.query.filter_by(id=campaign_id, user_id=current_user.id).first()
    else:
        campaign = Campaign.query.get(campaign_id)
    
    if not campaign:
        return jsonify({'error': 'Campaign not found'}), 404

    if request.method == 'GET':
        return jsonify(campaign.to_dict())

    elif request.method == 'PUT':
        try:
            data = request.get_json()
            
            # Update allowed fields
            updateable_fields = ['name', 'daily_volume', 'warmup_days', 'industry']
            for field in updateable_fields:
                if field in data:
                    setattr(campaign, field, data[field])

            campaign.updated_at = datetime.utcnow()
            db.session.commit()

            return jsonify({'success': True, 'message': 'Campaign updated', 'campaign': campaign.to_dict()})

        except Exception as e:
            logger.error(f"Campaign update error: {str(e)}")
            db.session.rollback()
            return jsonify({'success': False, 'message': 'Failed to update campaign'}), 500

    elif request.method == 'DELETE':
        try:
            db.session.delete(campaign)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Campaign deleted'})

        except Exception as e:
            logger.error(f"Campaign deletion error: {str(e)}")
            db.session.rollback()
            return jsonify({'success': False, 'message': 'Failed to delete campaign'}), 500

@app.route('/api/campaigns//start', methods=['POST'])
def start_campaign(campaign_id):
    # FIXED: Handle campaign access without strict user filtering
    if current_user.is_authenticated:
        campaign = Campaign.query.filter_by(id=campaign_id, user_id=current_user.id).first()
    else:
        campaign = Campaign.query.get(campaign_id)
    
    if not campaign:
        return jsonify({'error': 'Campaign not found'}), 404

    try:
        campaign.status = 'active'
        campaign.updated_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Campaign started: {campaign.name}")
        return jsonify({'success': True, 'message': 'Campaign started'})

    except Exception as e:
        logger.error(f"Campaign start error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to start campaign'}), 500

@app.route('/api/campaigns//pause', methods=['POST'])
def pause_campaign(campaign_id):
    # FIXED: Handle campaign access without strict user filtering
    if current_user.is_authenticated:
        campaign = Campaign.query.filter_by(id=campaign_id, user_id=current_user.id).first()
    else:
        campaign = Campaign.query.get(campaign_id)
    
    if not campaign:
        return jsonify({'error': 'Campaign not found'}), 404

    try:
        campaign.status = 'paused'
        campaign.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Campaign paused'})

    except Exception as e:
        logger.error(f"Campaign pause error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to pause campaign'}), 500

@app.route('/api/dashboard-stats')
def dashboard_stats():
    try:
        # FIXED: Get campaigns properly based on authentication state
        if current_user.is_authenticated:
            user_campaigns = Campaign.query.filter_by(user_id=current_user.id).all()
        else:
            # Get admin user's campaigns as default
            admin_user = User.query.first()
            if admin_user:
                user_campaigns = Campaign.query.filter_by(user_id=admin_user.id).all()
            else:
                user_campaigns = []
        
        total_campaigns = len(user_campaigns)
        active_campaigns = len([c for c in user_campaigns if c.status == 'active'])
        total_emails_sent = sum(c.emails_sent for c in user_campaigns)
        avg_success_rate = sum(c.success_rate for c in user_campaigns) / total_campaigns if total_campaigns > 0 else 0

        return jsonify({
            'total_campaigns': total_campaigns,
            'active_campaigns': active_campaigns,
            'emails_sent': total_emails_sent,
            'success_rate': round(avg_success_rate, 1)
        })

    except Exception as e:
        logger.error(f"Dashboard stats error: {str(e)}")
        return jsonify({'error': 'Failed to load stats'}), 500

@app.route('/api/providers')
def get_providers():
    """Get available SMTP providers"""
    return jsonify({
        'providers': {
            key: {
                'name': key.replace('_', ' ').title(),
                'help_text': config.get('help_text', ''),
                'requires_custom_host': key in ['custom_smtp', 'custom_ses']
            }
            for key, config in SMTP_PROVIDERS.items()
        }
    })

# Error Handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {str(error)}")
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Access forbidden'}), 403

# Initialize database
def create_tables():
    """Create database tables"""
    try:
        with app.app_context():
            db.create_all()
            create_default_user()
            logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")

# Application startup
if __name__ == '__main__':
    create_tables()
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)
