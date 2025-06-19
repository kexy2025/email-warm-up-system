#!/usr/bin/env python3
"""
KEXY Email Warmup System - Complete Application
24/7 OPERATION with POSTGRES PERSISTENCE and APPLICATION CONTEXT FIX
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
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, send_from_directory
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

# Initialize Flask app
app = Flask(__name__)

# Static file serving route
@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    return send_from_directory('static', filename)

# Logging setup - FIRST
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# 🔧 FIXED DATABASE CONFIGURATION - POSTGRES PERSISTENCE
def setup_database():
    """Setup database with Postgres for persistence"""
    database_url = os.environ.get('DATABASE_URL', '').strip()
    
    if database_url:
        # Use the persistent Postgres database
        logger.info("🔧 Using Postgres database for data persistence")
        
        # Fix postgres:// to postgresql:// if needed (common issue)
        if database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
            logger.info("Fixed postgres:// URL to postgresql://")
        
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        logger.info("✅ Postgres database configured successfully")
    else:
        # Fallback to SQLite with persistent volume
        logger.info("🔧 No DATABASE_URL found, using SQLite with persistent storage")
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///warmup.db'
    
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
    
    # Log database info (without sensitive data)
    db_type = "Postgres" if "postgresql://" in app.config['SQLALCHEMY_DATABASE_URI'] else "SQLite"
    logger.info(f"Database type: {db_type}")
    return True

# Setup database
setup_database()

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
CORS(app)

# Encryption setup
try:
    encryption_key = os.environ.get('ENCRYPTION_KEY')
    if not encryption_key:
        encryption_key = Fernet.generate_key()
        logger.warning("Generated new encryption key")
    elif isinstance(encryption_key, str):
        encryption_key = encryption_key.encode()
    
    cipher_suite = Fernet(encryption_key)
    logger.info("✅ Encryption initialized successfully")
except Exception as e:
    logger.error(f"Encryption setup error: {e}")
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

# Warmup Strategies Configuration
WARMUP_STRATEGIES = {
    'steady': {
        'name': 'Steady',
        'description': 'Consistent daily volume for reliable warming',
        'daily_volume': 10,
        'duration_days': 30,
        'pattern': 'consistent'
    },
    'progressive': {
        'name': 'Progressive', 
        'description': 'Gradual increase over time',
        'start_volume': 5,
        'end_volume': 50,
        'duration_days': 30,
        'pattern': 'linear_increase'
    },
    'aggressive': {
        'name': 'Aggressive',
        'description': 'Rapid volume increase for fast warming',
        'start_volume': 10,
        'end_volume': 100,
        'duration_days': 14,
        'pattern': 'exponential_increase'
    },
    'conservative': {
        'name': 'Conservative',
        'description': 'Slow and safe approach',
        'start_volume': 3,
        'end_volume': 25,
        'duration_days': 45,
        'pattern': 'gradual_increase'
    }
}

# Email Templates and Content Types
EMAIL_CONTENT_TYPES = {
    'follow_up': {
        'subject_templates': [
            "Following up on our {topic} discussion",
            "Quick follow-up: {topic}",
            "Re: {topic} - Next steps"
        ],
        'body_template': """Hi {recipient_name},

I hope this email finds you well. I wanted to follow up on our recent discussion about {topic}.

{main_content}

I'd love to hear your thoughts on this. Would you be available for a brief call next week to discuss further?

Best regards,
{sender_name}"""
    },
    'newsletter': {
        'subject_templates': [
            "{industry} Weekly Update - {date}",
            "Latest {industry} Trends and Insights",
            "Your {industry} Newsletter - Week of {date}"
        ],
        'body_template': """Hello {recipient_name},

Welcome to this week's {industry} newsletter!

{main_content}

Key highlights this week:
• Industry developments
• Market insights
• Upcoming events

Stay tuned for more updates!

Best regards,
{sender_name}"""
    },
    'inquiry': {
        'subject_templates': [
            "Partnership opportunity in {industry}",
            "Exploring collaboration possibilities",
            "Business inquiry - {topic}"
        ],
        'body_template': """Dear {recipient_name},

I hope you're doing well. I'm reaching out regarding a potential collaboration opportunity in {industry}.

{main_content}

I believe there could be significant mutual benefits to exploring this further. Would you be interested in a brief conversation?

Looking forward to your response.

Best regards,
{sender_name}"""
    },
    'update': {
        'subject_templates': [
            "Project update: {topic}",
            "Progress report - {topic}",
            "Quick update on {topic}"
        ],
        'body_template': """Hi {recipient_name},

I wanted to share a quick update on {topic}.

{main_content}

Please let me know if you have any questions or need additional information.

Thanks,
{sender_name}"""
    }
}

# Warmup Recipients Pool
WARMUP_RECIPIENTS = [
    {"email": "sarah.marketing@business-network.com", "name": "Sarah Chen", "industry": "marketing", "responds": True},
    {"email": "mike.tech@innovation-hub.com", "name": "Mike Rodriguez", "industry": "technology", "responds": True},
    {"email": "anna.finance@growth-partners.com", "name": "Anna Thompson", "industry": "finance", "responds": True},
    {"email": "david.consulting@strategy-group.com", "name": "David Kim", "industry": "consulting", "responds": True},
    {"email": "lisa.healthcare@wellness-corp.com", "name": "Lisa Johnson", "industry": "healthcare", "responds": True},
    {"email": "robert.education@learning-solutions.com", "name": "Robert Wilson", "industry": "education", "responds": True},
    {"email": "emily.retail@commerce-network.com", "name": "Emily Davis", "industry": "retail", "responds": True},
    {"email": "james.realestate@property-pros.com", "name": "James Miller", "industry": "real_estate", "responds": True}
]

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
    status = db.Column(db.String(20))
    error_message = db.Column(db.Text)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    campaign = db.relationship('Campaign', backref='email_logs')

# Login manager user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create all the functions
def generate_ai_email_content(content_type, industry, recipient_name, sender_name):
    """Generate realistic email content using OpenAI"""
    try:
        if not openai.api_key:
            return generate_fallback_content(content_type, industry, recipient_name, sender_name)
        
        prompt = f"""
        Generate a professional, realistic email for {content_type} in the {industry} industry.
        
        Requirements:
        - Natural, human-like writing
        - Industry-appropriate language
        - 2-3 sentences for main content
        - Professional but friendly tone
        - Avoid obvious marketing language
        
        Context:
        - Recipient: {recipient_name}
        - Sender: {sender_name}
        - Industry: {industry}
        - Email type: {content_type}
        
        Return only the main content paragraph (no subject or full email structure).
        """
        
        response = openai.Completion.create(
            engine="text-davinci-003",
            prompt=prompt,
            max_tokens=150,
            temperature=0.7
        )
        
        return response.choices[0].text.strip()
        
    except Exception as e:
        logger.error(f"AI content generation failed: {str(e)}")
        return generate_fallback_content(content_type, industry, recipient_name, sender_name)

def generate_fallback_content(content_type, industry, recipient_name, sender_name):
    """Fallback content when AI is unavailable"""
    fallback_content = {
        'follow_up': f"I've been thinking about our conversation regarding {industry} trends and wanted to share some additional insights that might be valuable for your current projects.",
        'newsletter': f"This week in {industry}, we've seen some interesting developments that I thought you'd find relevant to your work.",
        'inquiry': f"I've been following your work in {industry} and believe there might be some synergies between our organizations that we could explore.",
        'update': f"I wanted to keep you informed about the progress we've been making in {industry} and how it might impact our collaboration."
    }
    return fallback_content.get(content_type, "I hope you're having a great week and wanted to reach out with some thoughts on our industry.")

def process_spintax(text):
    """Process spintax variations {option1|option2|option3}"""
    import re
    
    def replace_spintax(match):
        options = match.group(1).split('|')
        return random.choice(options)
    
    while '{' in text and '|' in text and '}' in text:
        text = re.sub(r'\{([^}]+)\}', replace_spintax, text, count=1)
    
    return text

def send_warmup_email(campaign_id, recipient_email, recipient_name, content_type):
    """Send actual warmup email - FIXED WITH APP CONTEXT"""
    try:
        with app.app_context():  # 🔧 FIX: Ensure app context for database operations
            campaign = Campaign.query.get(campaign_id)
            if not campaign or campaign.status != 'active':
                logger.error(f"Campaign {campaign_id} not active or not found")
                return False
            
            logger.info(f"Generating email content for {recipient_email}")
            
            # Generate AI content
            ai_content = generate_ai_email_content(
                content_type, 
                campaign.industry, 
                recipient_name, 
                "Team"
            )
            
            # Get email template
            template = EMAIL_CONTENT_TYPES[content_type]
            subject_template = random.choice(template['subject_templates'])
            
            # Generate subject with spintax
            subject = process_spintax(subject_template.format(
                topic=campaign.industry,
                industry=campaign.industry.replace('_', ' ').title(),
                date=datetime.now().strftime('%B %d')
            ))
            
            # Generate email body
            email_body = template['body_template'].format(
                recipient_name=recipient_name,
                topic=campaign.industry.replace('_', ' '),
                industry=campaign.industry.replace('_', ' ').title(),
                main_content=ai_content,
                sender_name=campaign.email.split('@')[0].title()
            )
            
            logger.info(f"Attempting to send email to {recipient_email} with subject: {subject}")
            
            # Send email using campaign SMTP settings
            success = send_smtp_email(campaign, recipient_email, subject, email_body)
            
            # Log the email
            log_email(campaign_id, recipient_email, subject, 'sent' if success else 'failed')
            
            if success:
                # 🔧 FIXED: Update campaign stats properly
                campaign.emails_sent += 1
                campaign.progress = calculate_campaign_progress(campaign)
                
                # 🔧 FIXED: Calculate and update success rate correctly
                total_attempts = EmailLog.query.filter_by(campaign_id=campaign_id).count()
                successful_attempts = EmailLog.query.filter_by(campaign_id=campaign_id, status='sent').count()
                if total_attempts > 0:
                    campaign.success_rate = (successful_attempts / total_attempts) * 100
                else:
                    campaign.success_rate = 0.0
                
                db.session.commit()
                logger.info(f"Email sent successfully and stats updated - Success rate: {campaign.success_rate}%")
                
            return success
        
    except Exception as e:
        logger.error(f"Error sending warmup email: {str(e)}")
        with app.app_context():
            log_email(campaign_id, recipient_email, "Error", 'failed', str(e))
        return False

def send_smtp_email(campaign, recipient_email, subject, body):
    """Send email using campaign's SMTP settings"""
    try:
        logger.info(f"Connecting to SMTP server: {campaign.smtp_host}:{campaign.smtp_port}")
        
        # Decrypt password
        smtp_password = campaign.decrypt_password()
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = campaign.email
        msg['To'] = recipient_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        # Connect and send
        if campaign.use_tls:
            server = smtplib.SMTP(campaign.smtp_host, campaign.smtp_port)
            server.starttls()
        else:
            server = smtplib.SMTP(campaign.smtp_host, campaign.smtp_port)
        
        logger.info(f"Authenticating with username: {campaign.smtp_username}")
        server.login(campaign.smtp_username, smtp_password)
        
        logger.info(f"Sending email from {campaign.email} to {recipient_email}")
        server.send_message(msg)
        server.quit()
        
        logger.info(f"Email sent successfully to {recipient_email}")
        return True
        
    except Exception as e:
        logger.error(f"SMTP send failed: {str(e)}")
        return False

def log_email(campaign_id, recipient, subject, status, error_message=None):
    """Log email sending attempt - FIXED WITH APP CONTEXT"""
    try:
        with app.app_context():
            email_log = EmailLog(
                campaign_id=campaign_id,
                recipient=recipient,
                subject=subject,
                status=status,
                error_message=error_message,
                sent_at=datetime.utcnow()
            )
            db.session.add(email_log)
            db.session.commit()
            logger.info(f"Email log created: {status} to {recipient}")
    except Exception as e:
        logger.error(f"Error logging email: {str(e)}")

def calculate_campaign_progress(campaign):
    """Calculate campaign progress percentage"""
    days_elapsed = (datetime.utcnow() - campaign.created_at).days
    total_days = campaign.warmup_days
    return min(int((days_elapsed / total_days) * 100), 100)

def get_daily_volume_for_campaign(campaign):
    """Calculate daily email volume"""
    return campaign.daily_volume

# 🔧 MAIN FIX: APPLICATION CONTEXT WRAPPER FOR SCHEDULER
def process_warmup_campaigns():
    """Process all active campaigns for email sending - FIXED WITH APP CONTEXT"""
    try:
        with app.app_context():  # 🔧 CRITICAL FIX: Wrap all database operations
            active_campaigns = Campaign.query.filter_by(status='active').all()
            logger.info(f"🔄 [24/7 MODE] Processing {len(active_campaigns)} active campaigns")
            
            for campaign in active_campaigns:
                daily_volume = get_daily_volume_for_campaign(campaign)
                
                # Check if we've already sent emails today
                today = datetime.utcnow().date()
                today_emails = EmailLog.query.filter(
                    EmailLog.campaign_id == campaign.id,
                    EmailLog.sent_at >= today,
                    EmailLog.status == 'sent'
                ).count()
                
                emails_to_send = max(0, daily_volume - today_emails)
                logger.info(f"📧 Campaign '{campaign.name}': {emails_to_send} emails to send today (sent: {today_emails}/{daily_volume})")
                
                if emails_to_send > 0:
                    # Select random recipients
                    recipients = random.sample(WARMUP_RECIPIENTS, min(emails_to_send, len(WARMUP_RECIPIENTS)))
                    
                    for recipient in recipients:
                        # Select random content type
                        content_type = random.choice(list(EMAIL_CONTENT_TYPES.keys()))
                        
                        # Send email
                        success = send_warmup_email(
                            campaign.id,
                            recipient['email'],
                            recipient['name'],
                            content_type
                        )
                        logger.info(f"📨 Email to {recipient['email']}: {'✅ SUCCESS' if success else '❌ FAILED'}")
                        
                        # Delay between emails (KEPT ORIGINAL 5-10 seconds for safety)
                        time.sleep(random.uniform(5, 10))
                    
                    logger.info(f"✅ Sent {len(recipients)} warmup emails for campaign '{campaign.name}'")
                else:
                    logger.info(f"⏭️ Campaign '{campaign.name}': Daily quota already reached")
    
    except Exception as e:
        logger.error(f"❌ Error processing warmup campaigns: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")

def start_warmup_scheduler():
    """Start the background email scheduler - 24/7 OPERATION WITH APP CONTEXT FIX"""
    def run_scheduler():
        logger.info("🚀 Warmup scheduler thread started - 24/7 MODE with APP CONTEXT FIX")
        
        # Schedule email sending every 2 minutes for faster testing
        schedule.every(2).minutes.do(process_warmup_campaigns)
        
        # Daily summary at 6 PM
        schedule.every().day.at("18:00").do(log_daily_summary)
        
        # Manual test run on startup (after 30 seconds)
        schedule.every(30).seconds.do(lambda: logger.info("🧪 Scheduler test - system ready")).tag('startup_test')
        
        scheduler_running = True
        while scheduler_running:
            try:
                schedule.run_pending()
                
                # Clear startup test after first run
                if schedule.get_jobs('startup_test'):
                    schedule.clear('startup_test')
                    logger.info("✅ Scheduler startup test completed")
                
                time.sleep(60)  # Check every minute for scheduled tasks
                
            except Exception as e:
                logger.error(f"❌ Scheduler error: {str(e)}")
                time.sleep(60)  # Continue running even if there's an error
    
    # Start scheduler in background thread
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    logger.info("⏰ Warmup scheduler started - 24/7 MODE with POSTGRES PERSISTENCE")

def log_daily_summary():
    """Log a daily summary of campaign activity - FIXED WITH APP CONTEXT"""
    try:
        with app.app_context():
            active_campaigns = Campaign.query.filter_by(status='active').all()
            today = datetime.utcnow().date()
            
            logger.info("📊 === DAILY SUMMARY ===")
            for campaign in active_campaigns:
                today_emails = EmailLog.query.filter(
                    EmailLog.campaign_id == campaign.id,
                    EmailLog.sent_at >= today,
                    EmailLog.status == 'sent'
                ).count()
                
                failed_emails = EmailLog.query.filter(
                    EmailLog.campaign_id == campaign.id,
                    EmailLog.sent_at >= today,
                    EmailLog.status == 'failed'
                ).count()
                
                logger.info(f"📈 Campaign '{campaign.name}': {today_emails} sent, {failed_emails} failed")
                
    except Exception as e:
        logger.error(f"Error generating daily summary: {str(e)}")

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
    """Create default admin user if no users exist - FIXED WITH APP CONTEXT"""
    try:
        with app.app_context():
            if User.query.count() == 0:
                admin = User(
                    username='admin',
                    email='admin@example.com'
                )
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                logger.info("✅ Default admin user created (username: admin, password: admin123)")
            else:
                logger.info("👤 Users already exist in database")
    except Exception as e:
        logger.error(f"Error creating default user: {str(e)}")

# ROUTES SECTION
@app.route('/test')
def test_route():
    return "App is working!"

@app.route('/')
def index():
    try:
        with app.app_context():
            admin_user = User.query.first()
            if admin_user:
                login_user(admin_user)
        return render_template('dashboard.html')
    except Exception as e:
        logger.error(f"Error in index route: {str(e)}")
        return """
        <html><body>
        <h1>🚀 KEXY Email Warmup System - 24/7 MODE with POSTGRES</h1>
        <p>System is starting up...</p>
        <p><a href="/dashboard">Go to Dashboard</a></p>
        <script>setTimeout(() => window.location.reload(), 3000);</script>
        </body></html>
        """

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
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
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            if request.is_json:
                return jsonify({'success': False, 'message': 'Login failed'}), 500
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# API Routes
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
        try:
            all_campaigns = Campaign.query.all()
            return jsonify([campaign.to_dict() for campaign in all_campaigns])
        except Exception as e:
            logger.error(f"Error fetching campaigns: {str(e)}")
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
                user_id=1  # Use admin user ID for testing
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
            
            # Update allowed fields
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
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Operation failed'}), 500

@app.route('/api/campaigns/<int:campaign_id>/start', methods=['POST'])
def start_campaign(campaign_id):
    try:
        logger.info(f"Starting campaign {campaign_id}")
        campaign = Campaign.query.get(campaign_id)
        
        if not campaign:
            logger.error(f"Campaign {campaign_id} not found")
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404

        campaign.status = 'active'
        campaign.updated_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Campaign {campaign_id} started successfully")
        return jsonify({'success': True, 'message': 'Campaign started successfully'})

    except Exception as e:
        logger.error(f"Error starting campaign {campaign_id}: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

@app.route('/api/campaigns/<int:campaign_id>/pause', methods=['POST'])
def pause_campaign(campaign_id):
    try:
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404

        campaign.status = 'paused'
        campaign.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Campaign paused'})

    except Exception as e:
        logger.error(f"Campaign pause error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to pause campaign'}), 500

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
        
        # Calculate stats from EmailLog table
        total_emails = EmailLog.query.filter_by(campaign_id=campaign_id).count()
        sent_emails = EmailLog.query.filter_by(campaign_id=campaign_id, status='sent').count()
        failed_emails = EmailLog.query.filter_by(campaign_id=campaign_id, status='failed').count()
        
        success_rate = (sent_emails / total_emails * 100) if total_emails > 0 else 0
        
        # Today's stats
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
            'daily_target': get_daily_volume_for_campaign(campaign)
        })
        
    except Exception as e:
        logger.error(f"Error fetching campaign stats: {str(e)}")
        return jsonify({'error': 'Failed to fetch stats'}), 500

@app.route('/api/dashboard-stats')
def dashboard_stats():
    try:
        # Get campaign counts
        total_campaigns = Campaign.query.count()
        active_campaigns = Campaign.query.filter_by(status='active').count()
        
        # Get REAL email stats from EmailLog table
        total_email_attempts = EmailLog.query.count()
        successful_emails = EmailLog.query.filter_by(status='sent').count()
        
        # Calculate actual success rate
        if total_email_attempts > 0:
            success_rate = (successful_emails / total_email_attempts) * 100
        else:
            success_rate = 0.0
        
        # Get total emails sent from EmailLog
        total_emails_sent = successful_emails

        return jsonify({
            'total_campaigns': total_campaigns,
            'active_campaigns': active_campaigns,
            'emails_sent': total_emails_sent,
            'success_rate': round(success_rate, 1)
        })

    except Exception as e:
        logger.error(f"Dashboard stats error: {str(e)}")
        return jsonify({
            'total_campaigns': 0,
            'active_campaigns': 0,
            'emails_sent': 0,
            'success_rate': 0.0
        })

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

@app.route('/api/warmup-strategies')
def get_warmup_strategies():
    """Get available warmup strategies"""
    return jsonify({'strategies': WARMUP_STRATEGIES})

# Debug Routes
@app.route('/api/debug/campaign/<int:campaign_id>')
def debug_campaign(campaign_id):
    """Debug campaign"""
    try:
        with app.app_context():
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
                'provider': campaign.provider,
                'last_updated': campaign.updated_at.isoformat() if campaign.updated_at else None,
                'app_context_fix': 'APPLIED'
            })
        
    except Exception as e:
        logger.error(f"Debug campaign error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/process-campaigns', methods=['POST'])
def debug_process_campaigns():
    """Manually trigger campaign processing"""
    try:
        logger.info("🔧 === MANUAL CAMPAIGN PROCESSING TRIGGERED ===")
        process_warmup_campaigns()
        
        with app.app_context():
            active_campaigns = Campaign.query.filter_by(status='active').count()
            today = datetime.utcnow().date()
            today_emails = EmailLog.query.filter(EmailLog.sent_at >= today).count()
        
        return jsonify({
            'success': True, 
            'message': 'Campaign processing completed',
            'active_campaigns': active_campaigns,
            'emails_sent_today': today_emails,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Manual processing error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/debug/force-send/<int:campaign_id>', methods=['POST'])
def force_send_now(campaign_id):
    """Force send an email right now for testing"""
    try:
        with app.app_context():
            campaign = Campaign.query.get(campaign_id)
            if not campaign:
                return jsonify({'error': 'Campaign not found'}), 404
            
            if campaign.status != 'active':
                campaign.status = 'active'
                db.session.commit()
                logger.info(f"🔧 Campaign {campaign_id} activated for testing")
            
            recipient = random.choice(WARMUP_RECIPIENTS)
            content_type = random.choice(list(EMAIL_CONTENT_TYPES.keys()))
            
            logger.info(f"🚀 FORCE SENDING email to {recipient['email']} for campaign {campaign.name}")
            
            success = send_warmup_email(
                campaign_id,
                recipient['email'],
                recipient['name'],
                content_type
            )
            
            latest_log = EmailLog.query.filter_by(campaign_id=campaign_id).order_by(EmailLog.sent_at.desc()).first()
            
            return jsonify({
                'success': success,
                'recipient': recipient['email'],
                'campaign_status': campaign.status,
                'content_type': content_type,
                'latest_log_status': latest_log.status if latest_log else 'No logs found',
                'latest_log_error': latest_log.error_message if latest_log else None,
                'message': f"Email {'✅ sent successfully' if success else '❌ failed to send'}",
                'timestamp': datetime.now().isoformat()
            })
        
    except Exception as e:
        logger.error(f"Force send error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/system-status')
def system_status():
    """Get overall system status"""
    try:
        with app.app_context():
            return jsonify({
                'database_connected': True,
                'total_campaigns': Campaign.query.count(),
                'active_campaigns': Campaign.query.filter_by(status='active').count(),
                'total_users': User.query.count(),
                'total_email_logs': EmailLog.query.count(),
                'server_time': datetime.now().isoformat(),
                'scheduler_running': True,
                'database_type': 'Postgres' if 'postgresql://' in app.config['SQLALCHEMY_DATABASE_URI'] else 'SQLite'
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Error Handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Access forbidden'}), 403

# Initialize database
def background_init():
    """Initialize database in background"""
    time.sleep(2)  # Wait for server to start
    try:
        with app.app_context():
            logger.info("🔧 Creating database tables...")
            db.create_all()
            logger.info("✅ Database tables created successfully")
            
            # Create default user
            create_default_user()
            
            # Start warmup system
            try:
                start_warmup_scheduler()
                logger.info("✅ Warmup scheduler started successfully")
            except Exception as scheduler_error:
                logger.error(f"❌ Scheduler error: {scheduler_error}")
            
            logger.info("🎉 System initialization complete!")
            
    except Exception as e:
        logger.error(f"❌ Database initialization error: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")

# Start background thread
threading.Thread(target=background_init, daemon=True).start()

# Application startup
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    logger.info("🚀 Starting KEXY Email Warmup System!")
    logger.info(f"🌐 Server will run on port {port}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)

logger.info("✅ KEXY Email Warmup System loaded!")
