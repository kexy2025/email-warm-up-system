# KEXY Email Warmup System - Flask Application
# CORRECTED: Preserves all existing functionality + adds Amazon SES support

import os
import sys
import logging
from datetime import datetime, timedelta
from functools import wraps

# Flask and extensions (Preserved)
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re
import json

# Initialize Flask app (Preserved)
app = Flask(__name__)

# Configuration (Preserved)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///kexy_warmup.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True

# Initialize extensions (Preserved)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)

# Encryption for storing email passwords (Preserved)
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
cipher_suite = Fernet(ENCRYPTION_KEY)

# Configure logging (Preserved)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# CORRECTED: Enhanced SMTP provider configurations with Amazon SES
SMTP_PROVIDERS = {
    # Original providers (Preserved)
    'gmail': {
        'host': 'smtp.gmail.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'help_text': 'Gmail: Enable 2FA and use App Password'
    },
    'outlook': {
        'host': 'smtp-mail.outlook.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'help_text': 'Outlook: Enable 2FA and use App Password'
    },
    'yahoo': {
        'host': 'smtp.mail.yahoo.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'help_text': 'Yahoo: Enable 2FA and use App Password'
    },
    'custom_smtp': {
        'host': None,  # User-defined
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'help_text': 'Custom SMTP: Enter your server details'
    },

    # ADDED: Amazon SES regional configurations
    'amazon_ses_us_east_1': {
        'host': 'email-smtp.us-east-1.amazonaws.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'region': 'us-east-1',
        'service': 'ses',
        'help_text': 'Amazon SES US East 1: Use IAM Access Key ID and Secret Access Key'
    },
    'amazon_ses_us_west_2': {
        'host': 'email-smtp.us-west-2.amazonaws.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'region': 'us-west-2',
        'service': 'ses',
        'help_text': 'Amazon SES US West 2: Use IAM Access Key ID and Secret Access Key'
    },
    'amazon_ses_us_west_1': {
        'host': 'email-smtp.us-west-1.amazonaws.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'region': 'us-west-1',
        'service': 'ses',
        'help_text': 'Amazon SES US West 1: Use IAM Access Key ID and Secret Access Key'
    },
    'amazon_ses_eu_west_1': {
        'host': 'email-smtp.eu-west-1.amazonaws.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'region': 'eu-west-1',
        'service': 'ses',
        'help_text': 'Amazon SES EU West 1: Use IAM Access Key ID and Secret Access Key'
    },
    'amazon_ses_eu_central_1': {
        'host': 'email-smtp.eu-central-1.amazonaws.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'region': 'eu-central-1',
        'service': 'ses',
        'help_text': 'Amazon SES EU Central 1: Use IAM Access Key ID and Secret Access Key'
    },
    'amazon_ses_ap_southeast_1': {
        'host': 'email-smtp.ap-southeast-1.amazonaws.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'region': 'ap-southeast-1',
        'service': 'ses',
        'help_text': 'Amazon SES Asia Pacific Singapore: Use IAM Access Key ID and Secret Access Key'
    },
    'amazon_ses_ap_southeast_2': {
        'host': 'email-smtp.ap-southeast-2.amazonaws.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'region': 'ap-southeast-2',
        'service': 'ses',
        'help_text': 'Amazon SES Asia Pacific Sydney: Use IAM Access Key ID and Secret Access Key'
    },
    'amazon_ses_ap_northeast_1': {
        'host': 'email-smtp.ap-northeast-1.amazonaws.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'region': 'ap-northeast-1',
        'service': 'ses',
        'help_text': 'Amazon SES Asia Pacific Tokyo: Use IAM Access Key ID and Secret Access Key'
    },
    'amazon_ses_ca_central_1': {
        'host': 'email-smtp.ca-central-1.amazonaws.com',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'region': 'ca-central-1',
        'service': 'ses',
        'help_text': 'Amazon SES Canada Central: Use IAM Access Key ID and Secret Access Key'
    },
    'custom_ses': {
        'host': None,  # User-defined
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'service': 'ses',
        'help_text': 'Custom Amazon SES: Enter your region-specific endpoint'
    }
}

# Database Models (Preserved)
class User(UserMixin, db.Model):
    """User model for authentication and session management"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationship with campaigns
    campaigns = db.relationship('Campaign', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)

class Campaign(db.Model):
    """Campaign model for email warmup campaigns"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    provider = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(120), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    smtp_host = db.Column(db.String(255))
    smtp_port = db.Column(db.Integer, default=587)
    use_tls = db.Column(db.Boolean, default=True)
    status = db.Column(db.String(20), default='inactive')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime)
    
    # Foreign key to user
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def encrypt_password(self, password):
        """Encrypt and store the email password"""
        self.encrypted_password = cipher_suite.encrypt(password.encode()).decode()

    def decrypt_password(self):
        """Decrypt and return the email password"""
        return cipher_suite.decrypt(self.encrypted_password.encode()).decode()

class EmailLog(db.Model):
    """Email log model for tracking sent emails"""
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    to_email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    error_message = db.Column(db.Text)

    campaign = db.relationship('Campaign', backref=db.backref('email_logs', lazy=True))

# User loader for Flask-Login (Preserved)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper Functions (Preserved)
def encrypt_password(password):
    """Encrypt a password for secure storage"""
    return cipher_suite.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    """Decrypt a password for use"""
    return cipher_suite.decrypt(encrypted_password.encode()).decode()

# CORRECTED: Enhanced SMTP validation with Amazon SES support
def validate_smtp_connection(provider, email, username, password, smtp_host=None, smtp_port=587, use_tls=True):
    """
    Validate SMTP connection for various providers including Amazon SES
    Preserves existing validation while adding SES support
    """
    try:
        # Get provider configuration
        config = SMTP_PROVIDERS.get(provider, {})
        
        # Use custom host if provided, otherwise use provider default
        host = smtp_host if smtp_host else config.get('host')
        if not host:
            return False, f"SMTP host not configured for provider: {provider}"
        
        port = smtp_port or config.get('port', 587)
        
        # ADDED: Amazon SES specific validation
        if 'amazon_ses' in provider or provider == 'custom_ses':
            return validate_ses_connection(host, port, username, password, use_tls)
        
        # Original SMTP validation (Preserved)
        context = ssl.create_default_context()
        
        with smtplib.SMTP(host, port) as server:
            if use_tls:
                server.starttls(context=context)
            
            # Test authentication
            server.login(username, password)
            
            # Test sending capability (without actually sending)
            server.noop()
            
        return True, "SMTP connection successful"
        
    except smtplib.SMTPAuthenticationError as e:
        error_msg = f"Authentication failed: {str(e)}"
        if 'amazon_ses' in provider:
            error_msg += " (Check your IAM Access Key ID and Secret Access Key)"
        return False, error_msg
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {str(e)}"
    except Exception as e:
        return False, f"Connection error: {str(e)}"

# ADDED: Amazon SES specific validation
def validate_ses_connection(host, port, access_key_id, secret_access_key, use_tls=True):
    """
    Validate Amazon SES connection with specific SES checks
    """
    try:
        # Validate Access Key ID format
        if not access_key_id.startswith('AKIA'):
            return False, "Invalid AWS Access Key ID format (should start with 'AKIA')"
        
        # Validate Secret Access Key length
        if len(secret_access_key) < 20:
            return False, "Invalid AWS Secret Access Key (too short)"
        
        # Test SMTP connection
        context = ssl.create_default_context()
        
        with smtplib.SMTP(host, port) as server:
            if use_tls:
                server.starttls(context=context)
            
            # SES uses Access Key ID as username and Secret Access Key as password
            server.login(access_key_id, secret_access_key)
            server.noop()
            
        return True, "Amazon SES connection successful"
        
    except smtplib.SMTPAuthenticationError as e:
        return False, f"SES Authentication failed: {str(e)}. Check your IAM credentials and permissions."
    except Exception as e:
        return False, f"SES connection error: {str(e)}"

# Authentication Routes (Preserved)
@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember_me = request.form.get('remember_me', False)
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember_me)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """User logout route"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route"""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('register.html')
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Main Routes (Preserved)
@app.route('/')
@login_required
def dashboard():
    """Main dashboard route"""
    return render_template('dashboard.html', user=current_user)

# API Routes (Preserved and Enhanced)
@app.route('/api/user/session', methods=['GET'])
@login_required
def get_user_session():
    """Get current user session information"""
    return jsonify({
        'success': True,
        'user': {
            'id': current_user.id,
            'username': current_user.username,
            'email': current_user.email,
            'last_login': current_user.last_login.isoformat() if current_user.last_login else None
        }
    })

@app.route('/api/validate-smtp', methods=['POST'])
@login_required
def validate_smtp():
    """CORRECTED: Enhanced SMTP validation endpoint with Amazon SES support"""
    try:
        data = request.get_json()
        
        # Extract form data
        provider = data.get('provider')
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')
        smtp_host = data.get('smtp_host')
        smtp_port = data.get('smtp_port', 587)
        use_tls = data.get('use_tls', True)
        
        # Validate required fields
        if not all([provider, email, username, password]):
            return jsonify({
                'success': False,
                'message': 'Missing required fields'
            }), 400
        
        # Validate SMTP connection (now includes SES support)
        success, message = validate_smtp_connection(
            provider, email, username, password, smtp_host, smtp_port, use_tls
        )
        
        return jsonify({
            'success': success,
            'message': message
        })
        
    except Exception as e:
        logger.error(f"SMTP validation error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Validation error: {str(e)}'
        }), 500

@app.route('/api/campaigns', methods=['GET', 'POST'])
@login_required
def campaigns():
    """Campaign management endpoint"""
    if request.method == 'GET':
        # Get user's campaigns
        user_campaigns = Campaign.query.filter_by(user_id=current_user.id).all()
        
        campaigns_data = []
        for campaign in user_campaigns:
            campaigns_data.append({
                'id': campaign.id,
                'name': campaign.name,
                'email': campaign.email,
                'provider': campaign.provider,
                'status': campaign.status,
                'created_at': campaign.created_at.isoformat()
            })
        
        return jsonify({
            'success': True,
            'campaigns': campaigns_data
        })
    
    elif request.method == 'POST':
        # Create new campaign
        try:
            data = request.get_json()
            
            # Validate required fields
            required_fields = ['name', 'email', 'provider', 'username', 'password']
            if not all(field in data for field in required_fields):
                return jsonify({
                    'success': False,
                    'message': 'Missing required fields'
                }), 400
            
            # Create new campaign
            campaign = Campaign(
                name=data['name'],
                email=data['email'],
                provider=data['provider'],
                username=data['username'],
                smtp_host=data.get('smtp_host'),
                smtp_port=data.get('smtp_port', 587),
                use_tls=data.get('use_tls', True),
                user_id=current_user.id
            )
            
            # Encrypt and store password
            campaign.encrypt_password(data['password'])
            
            db.session.add(campaign)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Campaign created successfully',
                'campaign_id': campaign.id
            })
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Campaign creation error: {str(e)}")
            return jsonify({
                'success': False,
                'message': f'Error creating campaign: {str(e)}'
            }), 500

@app.route('/api/campaigns/', methods=['DELETE'])
@login_required
def delete_campaign(campaign_id):
    """Delete a campaign"""
    try:
        campaign = Campaign.query.filter_by(id=campaign_id, user_id=current_user.id).first()
        
        if not campaign:
            return jsonify({
                'success': False,
                'message': 'Campaign not found'
            }), 404
        
        db.session.delete(campaign)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Campaign deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Campaign deletion error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error deleting campaign: {str(e)}'
        }), 500

@app.route('/api/campaigns//start', methods=['POST'])
@login_required
def start_campaign(campaign_id):
    """Start a campaign"""
    try:
        campaign = Campaign.query.filter_by(id=campaign_id, user_id=current_user.id).first()
        
        if not campaign:
            return jsonify({
                'success': False,
                'message': 'Campaign not found'
            }), 404
        
        campaign.status = 'active'
        campaign.started_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Campaign started successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Campaign start error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error starting campaign: {str(e)}'
        }), 500

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def api_logout():
    """API logout endpoint"""
    logout_user()
    return jsonify({
        'success': True,
        'message': 'Logged out successfully'
    })

# Error Handlers (Preserved)
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# Database initialization (Preserved)
def create_tables():
    """Create database tables"""
    with app.app_context():
        db.create_all()
        logger.info("Database tables created successfully")

# Application startup (Preserved)
if __name__ == '__main__':
    create_tables()
    
    # Create admin user if it doesn't exist
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', email='admin@kexy.com')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            logger.info("Admin user created")
    
    # Run the application
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    app.run(host='0.0.0.0', port=port, debug=debug)
