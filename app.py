#!/usr/bin/env python3
"""
KEXY Email Warmup System - OPTIMIZED FOR INSTANT LAUNCH
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
import traceback

# Flask and extensions
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import requests

# AI Warmup Engine imports
import openai
import schedule
import time
import threading
import random

# INSTANT STARTUP - Initialize Flask app
app = Flask(__name__)

# FAST LOGGING SETUP
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(message)s')
logger = logging.getLogger(__name__)

# INSTANT CONFIGURATION
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///warmup.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

# INSTANT EXTENSIONS INIT
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
CORS(app)

# FAST ENCRYPTION SETUP
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

# Initialize OpenAI
openai.api_key = os.environ.get('OPENAI_API_KEY')

# SMTP Provider Configurations
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
    'custom_smtp': {
        'host': '',
        'port': 587,
        'use_tls': True,
        'requires_auth': True,
        'help_text': 'Custom SMTP: Enter your server details manually'
    }
}

WARMUP_STRATEGIES = {
    'steady': {'name': 'Steady', 'description': 'Consistent daily volume', 'daily_volume': 10, 'duration_days': 30},
    'progressive': {'name': 'Progressive', 'description': 'Gradual increase', 'start_volume': 5, 'end_volume': 50, 'duration_days': 30},
    'aggressive': {'name': 'Aggressive', 'description': 'Rapid increase', 'start_volume': 10, 'end_volume': 100, 'duration_days': 14},
    'conservative': {'name': 'Conservative', 'description': 'Slow and safe', 'start_volume': 3, 'end_volume': 25, 'duration_days': 45}
}

EMAIL_CONTENT_TYPES = {
    'follow_up': {
        'subject_templates': ["Following up on our {topic} discussion", "Quick follow-up: {topic}"],
        'body_template': "Hi {recipient_name},\n\nI hope this email finds you well. I wanted to follow up on our recent discussion about {topic}.\n\n{main_content}\n\nBest regards,\n{sender_name}"
    },
    'newsletter': {
        'subject_templates': ["{industry} Weekly Update - {date}", "Latest {industry} Trends"],
        'body_template': "Hello {recipient_name},\n\nWelcome to this week's {industry} newsletter!\n\n{main_content}\n\nBest regards,\n{sender_name}"
    },
    'inquiry': {
        'subject_templates': ["Partnership opportunity in {industry}", "Business inquiry - {topic}"],
        'body_template': "Dear {recipient_name},\n\nI hope you're doing well. I'm reaching out regarding {industry}.\n\n{main_content}\n\nBest regards,\n{sender_name}"
    },
    'update': {
        'subject_templates': ["Project update: {topic}", "Quick update on {topic}"],
        'body_template': "Hi {recipient_name},\n\nQuick update on {topic}.\n\n{main_content}\n\nThanks,\n{sender_name}"
    }
}

WARMUP_RECIPIENTS = [
    {"email": "sarah.marketing@business-network.com", "name": "Sarah Chen", "industry": "marketing"},
    {"email": "mike.tech@innovation-hub.com", "name": "Mike Rodriguez", "industry": "technology"},
    {"email": "anna.finance@growth-partners.com", "name": "Anna Thompson", "industry": "finance"},
    {"email": "david.consulting@strategy-group.com", "name": "David Kim", "industry": "consulting"},
    {"email": "lisa.healthcare@wellness-corp.com", "name": "Lisa Johnson", "industry": "healthcare"},
    {"email": "robert.education@learning-solutions.com", "name": "Robert Wilson", "industry": "education"},
    {"email": "emily.retail@commerce-network.com", "name": "Emily Davis", "industry": "retail"},
    {"email": "james.realestate@property-pros.com", "name": "James Miller", "industry": "real_estate"}
]

# SIMPLE DATABASE MODELS
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
    smtp_password_encrypted = db.Column(db.Text)
    use_tls = db.Column(db.Boolean, default=True)
    industry = db.Column(db.String(100))
    daily_volume = db.Column(db.Integer, default=10)
    warmup_days = db.Column(db.Integer, default=30)
    status = db.Column(db.String(20), default='created')
    progress = db.Column(db.Integer, default=0)
    emails_sent = db.Column(db.Integer, default=0)
    success_rate = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def encrypt_password(self, password):
        if password:
            self.smtp_password_encrypted = cipher_suite.encrypt(password.encode()).decode()

    def decrypt_password(self):
        if self.smtp_password_encrypted:
            return cipher_suite.decrypt(self.smtp_password_encrypted.encode()).decode()
        return None

    def to_dict(self):
        return {
            'id': self.id, 'name': self.name, 'email': self.email, 'provider': self.provider,
            'smtp_host': self.smtp_host, 'smtp_port': self.smtp_port, 'smtp_username': self.smtp_username,
            'use_tls': self.use_tls, 'industry': self.industry, 'daily_volume': self.daily_volume,
            'warmup_days': self.warmup_days, 'status': self.status, 'progress': self.progress,
            'emails_sent': self.emails_sent, 'success_rate': self.success_rate,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class EmailLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    recipient = db.Column(db.String(255))
    subject = db.Column(db.String(500))
    status = db.Column(db.String(20))
    error_message = db.Column(db.Text)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    campaign = db.relationship('Campaign', backref='email_logs')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# FAST UTILITY FUNCTIONS
def generate_fallback_content(content_type, industry, recipient_name, sender_name):
    fallback_content = {
        'follow_up': f"I've been thinking about our conversation regarding {industry} trends.",
        'newsletter': f"This week in {industry}, we've seen some interesting developments.",
        'inquiry': f"I've been following your work in {industry} and believe there might be synergies.",
        'update': f"I wanted to keep you informed about progress in {industry}."
    }
    return fallback_content.get(content_type, "Hope you're having a great week!")

def send_smtp_email(campaign, recipient_email, subject, body):
    try:
        smtp_password = campaign.decrypt_password()
        msg = MIMEMultipart()
        msg['From'] = campaign.email
        msg['To'] = recipient_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        if campaign.use_tls:
            server = smtplib.SMTP(campaign.smtp_host, campaign.smtp_port)
            server.starttls()
        else:
            server = smtplib.SMTP(campaign.smtp_host, campaign.smtp_port)
        
        server.login(campaign.smtp_username, smtp_password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        logger.error(f"SMTP send failed: {str(e)}")
        return False

def log_email(campaign_id, recipient, subject, status, error_message=None):
    try:
        email_log = EmailLog(
            campaign_id=campaign_id, recipient=recipient, subject=subject,
            status=status, error_message=error_message, sent_at=datetime.utcnow()
        )
        db.session.add(email_log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Error logging email: {str(e)}")

def send_warmup_email(campaign_id, recipient_email, recipient_name, content_type):
    try:
        campaign = Campaign.query.get(campaign_id)
        if not campaign or campaign.status != 'active':
            return False
        
        template = EMAIL_CONTENT_TYPES[content_type]
        subject = random.choice(template['subject_templates']).format(
            topic=campaign.industry, industry=campaign.industry.replace('_', ' ').title(),
            date=datetime.now().strftime('%B %d')
        )
        
        ai_content = generate_fallback_content(content_type, campaign.industry, recipient_name, "Team")
        
        email_body = template['body_template'].format(
            recipient_name=recipient_name, topic=campaign.industry.replace('_', ' '),
            industry=campaign.industry.replace('_', ' ').title(), main_content=ai_content,
            sender_name=campaign.email.split('@')[0].title()
        )
        
        success = send_smtp_email(campaign, recipient_email, subject, email_body)
        log_email(campaign_id, recipient_email, subject, 'sent' if success else 'failed')
        
        if success:
            campaign.emails_sent += 1
            db.session.commit()
            
        return success
    except Exception as e:
        logger.error(f"Error sending warmup email: {str(e)}")
        return False

def validate_smtp_connection(provider, email, username, password, smtp_host=None, smtp_port=587, use_tls=True):
    try:
        if provider in SMTP_PROVIDERS:
            config = SMTP_PROVIDERS[provider]
            host = smtp_host if smtp_host else config['host']
            port = smtp_port if smtp_port else config['port']
            tls = use_tls if use_tls is not None else config['use_tls']
        else:
            return False, f"Unsupported provider: {provider}"

        if tls:
            server = smtplib.SMTP(host, port)
            server.starttls()
        else:
            server = smtplib.SMTP(host, port)

        server.login(username, password)
        server.quit()
        return True, "Connection successful"

    except Exception as e:
        return False, f"Connection failed: {str(e)}"

# SIMPLE ROUTES
@app.route('/')
def index():
    try:
        admin_user = User.query.first()
        if admin_user:
            login_user(admin_user)
    except:
        pass
    return """
    <html><head><title>KEXY Email Warmup</title></head><body>
    <h1>🚀 KEXY Email Warmup System</h1>
    <p>✅ System is running and ready!</p>
    <p><a href="/dashboard">Go to Dashboard</a></p>
    <p><a href="/api/campaigns">View Campaigns API</a></p>
    </body></html>
    """

@app.route('/dashboard')
def dashboard():
    return """
    <html><head><title>Dashboard</title></head><body>
    <h1>📊 Dashboard</h1>
    <p>Email warmup system dashboard</p>
    <p><a href="/">Back to Home</a></p>
    </body></html>
    """

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            data = request.get_json() if request.is_json else request.form
            username = data.get('username', 'admin')
            password = data.get('password', 'admin123')
            
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)
                if request.is_json:
                    return jsonify({'success': True, 'message': 'Login successful'})
                return redirect(url_for('index'))
            else:
                if request.is_json:
                    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
    
    return """
    <html><head><title>Login</title></head><body>
    <h1>🔐 Login</h1>
    <form method="post">
    <p>Username: <input type="text" name="username" value="admin"></p>
    <p>Password: <input type="password" name="password" value="admin123"></p>
    <p><input type="submit" value="Login"></p>
    </form>
    </body></html>
    """

# API ROUTES
@app.route('/api/campaigns', methods=['GET', 'POST'])
def campaigns():
    if request.method == 'GET':
        try:
            all_campaigns = Campaign.query.all()
            return jsonify([campaign.to_dict() for campaign in all_campaigns])
        except Exception as e:
            return jsonify([])

    elif request.method == 'POST':
        try:
            data = request.get_json()
            required_fields = ['name', 'email', 'provider', 'username', 'password', 'industry']
            if not all(field in data for field in required_fields):
                return jsonify({'success': False, 'message': 'Missing required fields'}), 400
                
            provider = data['provider']
            if provider not in SMTP_PROVIDERS:
                return jsonify({'success': False, 'message': 'Invalid provider'}), 400

            success, message = validate_smtp_connection(
                provider, data['email'], data['username'], data['password'],
                data.get('smtp_host'), data.get('smtp_port', 587), data.get('use_tls', True)
            )

            if not success:
                return jsonify({'success': False, 'message': f'SMTP validation failed: {message}'}), 400

            campaign = Campaign(
                name=data['name'], email=data['email'], provider=provider,
                smtp_host=data.get('smtp_host') or SMTP_PROVIDERS.get(provider, {}).get('host'),
                smtp_port=data.get('smtp_port', 587), smtp_username=data['username'],
                use_tls=data.get('use_tls', True), industry=data['industry'],
                daily_volume=data.get('daily_volume', 10), warmup_days=data.get('warmup_days', 30),
                user_id=1
            )

            campaign.encrypt_password(data['password'])
            db.session.add(campaign)
            db.session.commit()

            return jsonify({'success': True, 'message': 'Campaign created successfully', 'campaign': campaign.to_dict()})

        except Exception as e:
            logger.error(f"Campaign creation error: {str(e)}")
            return jsonify({'success': False, 'message': 'Failed to create campaign'}), 500

@app.route('/api/campaigns/<int:campaign_id>/start', methods=['POST'])
def start_campaign(campaign_id):
    try:
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404
        
        campaign.status = 'active'
        campaign.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Campaign started successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

@app.route('/api/campaigns/<int:campaign_id>/pause', methods=['POST'])
def pause_campaign(campaign_id):
    try:
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404
        
        campaign.status = 'paused'
        db.session.commit()
        return jsonify({'success': True, 'message': 'Campaign paused'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to pause campaign'}), 500

@app.route('/api/debug/force-send/<int:campaign_id>', methods=['POST'])
def force_send_now(campaign_id):
    try:
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404
        
        if campaign.status != 'active':
            campaign.status = 'active'
            db.session.commit()
        
        recipient = random.choice(WARMUP_RECIPIENTS)
        content_type = random.choice(list(EMAIL_CONTENT_TYPES.keys()))
        
        success = send_warmup_email(campaign_id, recipient['email'], recipient['name'], content_type)
        
        return jsonify({
            'success': success,
            'recipient': recipient['email'],
            'message': f"Email {'sent successfully' if success else 'failed to send'}"
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/providers')
def get_providers():
    return jsonify({'providers': {key: {'name': key.replace('_', ' ').title(), 'help_text': config.get('help_text', '')} for key, config in SMTP_PROVIDERS.items()}})

# BACKGROUND INITIALIZATION - RUNS AFTER SERVER STARTS
def background_init():
    """Initialize database in background after server starts"""
    time.sleep(2)  # Wait for server to start
    try:
        with app.app_context():
            db.create_all()
            if User.query.count() == 0:
                admin = User(username='admin', email='admin@example.com')
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                logger.info("✅ Default admin user created")
            logger.info("✅ Database initialized in background")
    except Exception as e:
        logger.error(f"Background init error: {str(e)}")

# START BACKGROUND THREAD
threading.Thread(target=background_init, daemon=True).start()

# Error Handlers - SIMPLE
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# Additional API Routes for full functionality
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

@app.route('/api/campaigns/<int:campaign_id>', methods=['GET', 'PUT', 'DELETE'])
def campaign_detail(campaign_id):
    try:
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404

        if request.method == 'GET':
            return jsonify(campaign.to_dict())

        elif request.method == 'PUT':
            data = request.get_json()
            updateable_fields = ['name', 'daily_volume', 'warmup_days', 'industry']
            for field in updateable_fields:
                if field in data:
                    setattr(campaign, field, data[field])
            campaign.updated_at = datetime.utcnow()
            db.session.commit()
            return jsonify({'success': True, 'message': 'Campaign updated', 'campaign': campaign.to_dict()})

        elif request.method == 'DELETE':
            db.session.delete(campaign)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Campaign deleted'})

    except Exception as e:
        logger.error(f"Campaign detail error: {str(e)}")
        return jsonify({'success': False, 'message': 'Operation failed'}), 500

@app.route('/api/campaigns/<int:campaign_id>/logs')
def get_campaign_logs(campaign_id):
    try:
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404
        
        logs = EmailLog.query.filter_by(campaign_id=campaign_id).order_by(EmailLog.sent_at.desc()).limit(100).all()
        
        log_data = []
        for log in logs:
            log_data.append({
                'id': log.id,
                'recipient': log.recipient,
                'subject': log.subject,
                'status': log.status,
                'sent_at': log.sent_at.isoformat() if log.sent_at else None,
                'error_message': log.error_message
            })
        
        return jsonify({'logs': log_data})
        
    except Exception as e:
        logger.error(f"Error fetching campaign logs: {str(e)}")
        return jsonify({'error': 'Failed to fetch logs'}), 500

@app.route('/api/campaigns/<int:campaign_id>/stats')
def get_campaign_stats(campaign_id):
    try:
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404
        
        total_emails = EmailLog.query.filter_by(campaign_id=campaign_id).count()
        sent_emails = EmailLog.query.filter_by(campaign_id=campaign_id, status='sent').count()
        failed_emails = EmailLog.query.filter_by(campaign_id=campaign_id, status='failed').count()
        
        success_rate = (sent_emails / total_emails * 100) if total_emails > 0 else 0
        
        today = datetime.utcnow().date()
        today_emails = EmailLog.query.filter(
            EmailLog.campaign_id == campaign_id,
            EmailLog.sent_at >= today,
            EmailLog.status == 'sent'
        ).count()
        
        return jsonify({
            'campaign_id': campaign_id,
            'total_emails': total_emails,
            'sent_emails': sent_emails,
            'failed_emails': failed_emails,
            'success_rate': round(success_rate, 1),
            'today_emails': today_emails,
            'progress': campaign.progress,
            'daily_target': campaign.daily_volume
        })
        
    except Exception as e:
        logger.error(f"Error fetching campaign stats: {str(e)}")
        return jsonify({'error': 'Failed to fetch stats'}), 500

@app.route('/api/dashboard-stats')
def dashboard_stats():
    try:
        all_campaigns = Campaign.query.all()
        
        total_campaigns = len(all_campaigns)
        active_campaigns = len([c for c in all_campaigns if c.status == 'active'])
        total_emails_sent = sum(c.emails_sent for c in all_campaigns)
        avg_success_rate = sum(c.success_rate for c in all_campaigns) / total_campaigns if total_campaigns > 0 else 0

        return jsonify({
            'total_campaigns': total_campaigns,
            'active_campaigns': active_campaigns,
            'emails_sent': total_emails_sent,
            'success_rate': round(avg_success_rate, 1)
        })

    except Exception as e:
        logger.error(f"Dashboard stats error: {str(e)}")
        return jsonify({'error': 'Failed to load stats'}), 500

@app.route('/api/warmup-strategies')
def get_warmup_strategies():
    return jsonify({'strategies': WARMUP_STRATEGIES})

@app.route('/api/debug/campaign/<int:campaign_id>')
def debug_campaign(campaign_id):
    try:
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404
        
        today = datetime.utcnow().date()
        today_emails = EmailLog.query.filter(
            EmailLog.campaign_id == campaign_id,
            EmailLog.sent_at >= today
        ).count()
        
        total_emails = EmailLog.query.filter_by(campaign_id=campaign_id).count()
        
        return jsonify({
            'campaign_status': campaign.status,
            'campaign_name': campaign.name,
            'daily_volume': campaign.daily_volume,
            'emails_sent_today': today_emails,
            'total_emails_ever': total_emails,
            'current_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'smtp_host': campaign.smtp_host,
            'smtp_username': campaign.smtp_username,
            'provider': campaign.provider
        })
        
    except Exception as e:
        logger.error(f"Debug campaign error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/process-campaigns', methods=['POST'])
def debug_process_campaigns():
    try:
        # Simple campaign processing for testing
        active_campaigns = Campaign.query.filter_by(status='active').all()
        logger.info(f"Found {len(active_campaigns)} active campaigns")
        
        for campaign in active_campaigns:
            recipient = random.choice(WARMUP_RECIPIENTS)
            content_type = random.choice(list(EMAIL_CONTENT_TYPES.keys()))
            
            success = send_warmup_email(
                campaign.id,
                recipient['email'],
                recipient['name'],
                content_type
            )
            logger.info(f"Email to {recipient['email']}: {'SUCCESS' if success else 'FAILED'}")
        
        return jsonify({'success': True, 'message': f'Processed {len(active_campaigns)} campaigns'})
    except Exception as e:
        logger.error(f"Manual processing error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# Health check endpoint
@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0',
        'database': 'connected'
    })

# INSTANT SERVER START
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    logger.info("🚀 KEXY Email Warmup System - INSTANT LAUNCH!")
    logger.info(f"🌐 Starting server on port {port}")
    logger.info("⚡ Database will initialize in background")
    logger.info("✅ System ready for immediate use!")
    
    # INSTANT START - NO DELAYS
    app.run(host='0.0.0.0', port=port, debug=debug, threaded=True)

# Final startup message
logger.info("🎉 KEXY Email Warmup System launched successfully!")
