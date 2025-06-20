#!/usr/bin/env python3

import os
import logging

# Add this debugging section right at the start
print("🚀 Starting app.py...")
print(f"📍 Current working directory: {os.getcwd()}")
print(f"🔧 Python path: {os.environ.get('PYTHONPATH', 'Not set')}")
print(f"🌐 PORT environment variable: {os.environ.get('PORT', 'Not set')}")
print(f"🗄️ DATABASE_URL exists: {bool(os.environ.get('DATABASE_URL'))}")

try:
    from datetime import datetime, timedelta
    print("✅ datetime imported successfully")
except Exception as e:
    print(f"❌ datetime import failed: {e}")

try:
    import smtplib
    print("✅ smtplib imported successfully")  
except Exception as e:
    print(f"❌ smtplib import failed: {e}")

# Continue with your existing imports...

from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import threading
import time
import secrets
import uuid
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Safe imports with fallback handling
try:
    import schedule
    SCHEDULE_AVAILABLE = True
    print("✅ Schedule module loaded successfully")
except ImportError:
    SCHEDULE_AVAILABLE = False
    schedule = None
    print("⚠️ Schedule module not available - scheduling features disabled")

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    import atexit
    APSCHEDULER_AVAILABLE = True
    print("✅ APScheduler loaded successfully")
except ImportError:
    APSCHEDULER_AVAILABLE = False
    print("⚠️ APScheduler not available")

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Enhanced Railway-compatible database configuration with auto-migration
database_url = os.environ.get('DATABASE_URL', '').strip()
if database_url and not database_url.startswith('sqlite'):
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    logger = logging.getLogger(__name__)
    logger.info("🔧 Using PostgreSQL database - AUTO-MIGRATION ENABLED")
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///warmup.db'
    logger = logging.getLogger(__name__)
    logger.info("🔧 Using SQLite database in app directory")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'pool_timeout': 20,
    'max_overflow': 0
}

# Email configuration for password reset
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@kexy.com')

# Session configuration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Initialize scheduler if available
scheduler = None
if APSCHEDULER_AVAILABLE:
    try:
        scheduler = BackgroundScheduler()
        scheduler.start()
        atexit.register(lambda: scheduler.shutdown() if scheduler else None)
        print("✅ APScheduler initialized successfully")
    except Exception as e:
        print(f"⚠️ APScheduler initialization failed: {e}")
        scheduler = None

# Enhanced SMTP Providers Configuration
SMTP_PROVIDERS = {
    'gmail': {
        'host': 'smtp.gmail.com',
        'port': 587,
        'name': 'Gmail',
        'help_text': 'For Gmail: Enable 2-Factor Authentication and generate an App Password. Use your Gmail address as username.'
    },
    'outlook': {
        'host': 'smtp-mail.outlook.com',
        'port': 587,
        'name': 'Outlook/Hotmail',
        'help_text': 'For Outlook: Enable 2-Factor Authentication and generate an App Password. Use your Outlook email as username.'
    },
    'yahoo': {
        'host': 'smtp.mail.yahoo.com',
        'port': 587,
        'name': 'Yahoo Mail',
        'help_text': 'For Yahoo: Enable 2-Factor Authentication and generate an App Password for Mail.'
    },
    'amazon_ses_us_east_1': {
        'host': 'email-smtp.us-east-1.amazonaws.com',
        'port': 587,
        'name': 'Amazon SES (US East 1)',
        'help_text': 'Amazon SES: Use IAM Access Key ID as username and Secret Access Key as password.'
    },
    'amazon_ses_us_west_2': {
        'host': 'email-smtp.us-west-2.amazonaws.com',
        'port': 587,
        'name': 'Amazon SES (US West 2)',
        'help_text': 'Amazon SES: Use IAM Access Key ID as username and Secret Access Key as password.'
    },
    'amazon_ses_eu_west_1': {
        'host': 'email-smtp.eu-west-1.amazonaws.com',
        'port': 587,
        'name': 'Amazon SES (EU West 1)',
        'help_text': 'Amazon SES: Use IAM Access Key ID as username and Secret Access Key as password.'
    },
    'sendgrid': {
        'host': 'smtp.sendgrid.net',
        'port': 587,
        'name': 'SendGrid',
        'help_text': 'SendGrid: Use "apikey" as username and your SendGrid API key as password.'
    },
    'mailgun': {
        'host': 'smtp.mailgun.org',
        'port': 587,
        'name': 'Mailgun',
        'help_text': 'Mailgun: Use your Mailgun SMTP username and password from your domain settings.'
    }
}

# Enhanced Email Content Templates
EMAIL_CONTENT_TYPES = {
    'follow_up': {
        'subject_templates': [
            "Following up on our {topic} discussion",
            "Quick follow-up: {topic}",
            "Re: {topic} - Next steps",
            "Thoughts on our {topic} conversation"
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
            "Your {industry} Newsletter - Week of {date}",
            "Weekly {industry} Roundup"
        ],
        'body_template': """Hello {recipient_name},

Welcome to this week's {industry} newsletter!

{main_content}

Key highlights this week:
• Industry developments and market trends
• New opportunities and insights
• Upcoming events and webinars

Thank you for your continued interest!

Best regards,
{sender_name}"""
    },
    'inquiry': {
        'subject_templates': [
            "Partnership opportunity in {industry}",
            "Exploring collaboration possibilities",
            "Business inquiry - {topic}",
            "Potential collaboration in {industry}"
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
            "Quick update on {topic}",
            "{topic} - Latest developments"
        ],
        'body_template': """Hi {recipient_name},

I wanted to share a quick update on {topic}.

{main_content}

Please let me know if you have any questions or need additional information.

Thanks,
{sender_name}"""
    }
}

# Enhanced Warmup Recipients Pool
WARMUP_RECIPIENTS = [
    {"email": "sarah.marketing@business-network.com", "name": "Sarah Chen", "industry": "marketing", "responds": True},
    {"email": "mike.tech@innovation-hub.com", "name": "Mike Rodriguez", "industry": "technology", "responds": True},
    {"email": "anna.finance@growth-partners.com", "name": "Anna Thompson", "industry": "finance", "responds": True},
    {"email": "david.consulting@strategy-group.com", "name": "David Kim", "industry": "consulting", "responds": True},
    {"email": "lisa.healthcare@wellness-corp.com", "name": "Lisa Johnson", "industry": "healthcare", "responds": True},
    {"email": "robert.education@learning-solutions.com", "name": "Robert Wilson", "industry": "education", "responds": True},
    {"email": "emily.retail@commerce-network.com", "name": "Emily Davis", "industry": "retail", "responds": True},
    {"email": "james.realestate@property-pros.com", "name": "James Miller", "industry": "real_estate", "responds": True},
    {"email": "alex.startup@entrepreneur-hub.com", "name": "Alex Parker", "industry": "technology", "responds": True},
    {"email": "maria.design@creative-studio.com", "name": "Maria Lopez", "industry": "marketing", "responds": True}
]

# Enhanced Database Models with Authentication
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')  # user, admin, demo
    email_verified = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    campaigns = db.relationship('Campaign', backref='user', lazy=True, cascade='all, delete-orphan')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role == 'admin'
    
    def is_demo(self):
        return self.role == 'demo'
    
    def get_campaign_limit(self):
        if self.role == 'admin':
            return float('inf')
        elif self.role == 'demo':
            return 1
        else:
            return 10
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'email_verified': self.email_verified,
            'is_active': self.is_active,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f'<User {self.username}>'

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    provider = db.Column(db.String(50), nullable=False)
    smtp_host = db.Column(db.String(255))
    smtp_port = db.Column(db.Integer, default=587)
    smtp_username = db.Column(db.String(255))
    smtp_password = db.Column(db.String(500))
    industry = db.Column(db.String(100))
    daily_volume = db.Column(db.Integer, default=10)
    warmup_days = db.Column(db.Integer, default=30)
    status = db.Column(db.String(20), default='created')
    emails_sent = db.Column(db.Integer, default=0)
    success_rate = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'provider': self.provider,
            'industry': self.industry,
            'daily_volume': self.daily_volume,
            'warmup_days': self.warmup_days,
            'status': self.status,
            'emails_sent': self.emails_sent,
            'success_rate': round(self.success_rate, 1),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'user_id': self.user_id
        }

    def __repr__(self):
        return f'<Campaign {self.name}>'

class EmailLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    recipient = db.Column(db.String(255))
    subject = db.Column(db.String(500))
    status = db.Column(db.String(20))
    error_message = db.Column(db.Text)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<EmailLog {self.recipient}>'

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def is_expired(self):
        return datetime.utcnow() > self.expires_at

    def __repr__(self):
        return f'<PasswordResetToken {self.token}>'

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    ip_address = db.Column(db.String(45))
    success = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<LoginAttempt {self.email}>'

# Login Manager
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Decorators
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def demo_restricted(f):
    @wraps(f)
    @login_required  
    def decorated_function(*args, **kwargs):
        if current_user.is_demo():
            return jsonify({'error': 'Demo accounts cannot perform this action'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Authentication Helper Functions
def generate_reset_token():
    return secrets.token_urlsafe(32)

def send_reset_email(user, token):
    try:
        reset_url = url_for('reset_password', token=token, _external=True)
        html_body = f"""
        <h2>Password Reset Request</h2>
        <p>Hello {user.username},</p>
        <p>You requested a password reset for your KEXY Email Warmup account.</p>
        <p>Click the link below to reset your password:</p>
        <p><a href="{reset_url}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this reset, please ignore this email.</p>
        <br>
        <p>Best regards,<br>KEXY Email Warmup Team</p>
        """
        
        msg = Message(
            'Password Reset Request - KEXY Email Warmup',
            recipients=[user.email],
            html=html_body
        )
        mail.send(msg)
        return True
    except Exception as e:
        logger.error(f"Failed to send reset email: {str(e)}")
        return False

def log_login_attempt(email, ip_address, success):
    try:
        attempt = LoginAttempt(
            email=email,
            ip_address=ip_address,
            success=success
        )
        db.session.add(attempt)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to log login attempt: {str(e)}")

def create_demo_user():
    """Create demo user with sample campaign"""
    try:
        demo_user = User.query.filter_by(role='demo').first()
        if not demo_user:
            demo_user = User(
                username='demo',
                email='demo@kexy.com',
                password_hash=generate_password_hash('demo123'),
                role='demo',
                email_verified=True,
                is_active=True
            )
            db.session.add(demo_user)
            db.session.commit()
            
            # Create sample campaign for demo user
            demo_campaign = Campaign(
                name='Demo Email Warmup Campaign',
                email='demo@example.com',
                provider='gmail',
                smtp_host='smtp.gmail.com',
                smtp_port=587,
                smtp_username='demo@example.com',
                smtp_password='demo-password',
                industry='marketing',
                daily_volume=5,
                warmup_days=15,
                status='paused',
                emails_sent=25,
                success_rate=85.5,
                user_id=demo_user.id
            )
            db.session.add(demo_campaign)
            db.session.commit()
            
            logger.info("Demo user and sample campaign created")
        return demo_user
    except Exception as e:
        logger.error(f"Failed to create demo user: {str(e)}")
        return None

# Email Generation Functions (keeping existing)
def generate_fallback_content(content_type, industry, recipient_name, sender_name):
    """Generate fallback email content"""
    content_variations = {
        'follow_up': [
            f"I've been thinking about our conversation regarding {industry} trends and wanted to share some additional insights.",
            f"Following up on our {industry} discussion, I found some interesting developments that might interest you.",
            f"Hope you're doing well! I wanted to continue our conversation about {industry} opportunities."
        ],
        'newsletter': [
            f"This week in {industry}, we've seen some exciting developments that I thought you'd find valuable.",
            f"Here are the latest {industry} trends and insights that are shaping the industry.",
            f"Our weekly {industry} roundup brings you the most important updates and opportunities."
        ],
        'inquiry': [
            f"I've been following your work in {industry} and believe there might be some great synergies.",
            f"Your expertise in {industry} caught my attention, and I'd love to explore potential collaboration.",
            f"I'm reaching out because of your reputation in {industry} and a potential opportunity."
        ],
        'update': [
            f"Wanted to keep you informed about the latest progress in {industry} developments.",
            f"Here's a quick update on the {industry} project we've been working on.",
            f"Sharing some important updates about our {industry} initiatives."
        ]
    }
    
    variations = content_variations.get(content_type, [
        "Hope you're having a great week! Wanted to reach out with some thoughts."
    ])
    
    return random.choice(variations)

def process_spintax(text):
    """Process spintax variations {option1|option2|option3}"""
    import re
    
    def replace_spintax(match):
        options = match.group(1).split('|')
        return random.choice(options)
    
    while '{' in text and '|' in text and '}' in text:
        text = re.sub(r'\{([^}]+)\}', replace_spintax, text, count=1)
    
    return text

# Enhanced Email Sending Functions (user-aware)
def send_warmup_email(campaign_id, recipient_email, recipient_name, content_type):
    """Send warmup email with enhanced error handling"""
    try:
        with app.app_context():
            campaign = db.session.get(Campaign, campaign_id)
            if not campaign or campaign.status != 'active':
                logger.error(f"Campaign {campaign_id} not active or not found")
                return False
            
            # Check if user is demo (demo campaigns don't actually send emails)
            user = db.session.get(User, campaign.user_id)
            if user and user.is_demo():
                logger.info(f"Demo campaign {campaign_id} - simulated email send to {recipient_email}")
                log_email(campaign_id, recipient_email, "Demo Email", 'sent')
                campaign.emails_sent += 1
                update_campaign_success_rate(campaign_id)
                db.session.commit()
                return True
            
            logger.info(f"Generating email content for {recipient_email}")
            
            # Generate content
            ai_content = generate_fallback_content(
                content_type, 
                campaign.industry or 'business', 
                recipient_name, 
                campaign.email.split('@')[0].title()
            )
            
            # Get email template
            template = EMAIL_CONTENT_TYPES[content_type]
            subject_template = random.choice(template['subject_templates'])
            
            # Generate subject
            subject = process_spintax(subject_template.format(
                topic=campaign.industry or 'business',
                industry=(campaign.industry or 'business').replace('_', ' ').title(),
                date=datetime.now().strftime('%B %d')
            ))
            
            # Generate email body
            email_body = template['body_template'].format(
                recipient_name=recipient_name,
                topic=(campaign.industry or 'business').replace('_', ' '),
                industry=(campaign.industry or 'business').replace('_', ' ').title(),
                main_content=ai_content,
                sender_name=campaign.email.split('@')[0].title()
            )
            
            logger.info(f"Attempting to send email to {recipient_email}")
            
            # Send email
            success = send_smtp_email(campaign, recipient_email, subject, email_body)
            
            # Log the email
            log_email(campaign_id, recipient_email, subject, 'sent' if success else 'failed')
            
            if success:
                # Update campaign stats
                campaign.emails_sent += 1
                update_campaign_success_rate(campaign_id)
                db.session.commit()
                logger.info(f"Email sent successfully to {recipient_email}")
                
            return success
        
    except Exception as e:
        logger.error(f"Error sending warmup email: {str(e)}")
        with app.app_context():
            log_email(campaign_id, recipient_email, "Error", 'failed', str(e))
        return False

def send_smtp_email(campaign, recipient_email, subject, body):
    """Send email with enhanced error handling"""
    try:
        logger.info(f"Connecting to SMTP server: {campaign.smtp_host}:{campaign.smtp_port}")
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = campaign.email
        msg['To'] = recipient_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        # Connect and send
        server = smtplib.SMTP(campaign.smtp_host, campaign.smtp_port)
        server.starttls()
        server.login(campaign.smtp_username, campaign.smtp_password)
        server.send_message(msg)
        server.quit()
        
        logger.info(f"Email sent successfully to {recipient_email}")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP Authentication failed: {str(e)}")
        return False
    except smtplib.SMTPRecipientsRefused as e:
        logger.error(f"Recipient refused: {str(e)}")
        return False
    except smtplib.SMTPServerDisconnected as e:
        logger.error(f"SMTP server disconnected: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"SMTP send failed: {str(e)}")
        return False

def log_email(campaign_id, recipient, subject, status, error_message=None):
    """Log email sending attempt"""
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

def update_campaign_success_rate(campaign_id):
    """Update campaign success rate"""
    try:
        total_attempts = EmailLog.query.filter_by(campaign_id=campaign_id).count()
        successful_attempts = EmailLog.query.filter_by(campaign_id=campaign_id, status='sent').count()
        
        campaign = db.session.get(Campaign, campaign_id)
        if campaign and total_attempts > 0:
            campaign.success_rate = (successful_attempts / total_attempts) * 100
        else:
            campaign.success_rate = 0.0
            
    except Exception as e:
        logger.error(f"Error updating success rate: {str(e)}")

def calculate_campaign_progress(campaign):
    """Calculate campaign progress percentage"""
    try:
        days_elapsed = (datetime.utcnow() - campaign.created_at).days
        total_days = campaign.warmup_days
        return min(int((days_elapsed / total_days) * 100), 100)
    except:
        return 0

# Background Scheduler Functions (safe scheduling)
def process_warmup_campaigns():
    """Process all active campaigns for email sending"""
    try:
        with app.app_context():
            active_campaigns = Campaign.query.filter_by(status='active').all()
            logger.info(f"🔄 Processing {len(active_campaigns)} active campaigns")
            
            for campaign in active_campaigns:
                try:
                    # Check if user account is active
                    user = db.session.get(User, campaign.user_id)
                    if not user or not user.is_active:
                        logger.info(f"⏭️ Skipping campaign '{campaign.name}': User account inactive")
                        continue
                    
                    # Check daily quota
                    today = datetime.utcnow().date()
                    today_emails = EmailLog.query.filter(
                        EmailLog.campaign_id == campaign.id,
                        EmailLog.sent_at >= today,
                        EmailLog.status == 'sent'
                    ).count()
                    
                    emails_to_send = max(0, campaign.daily_volume - today_emails)
                    
                    if emails_to_send > 0:
                        # Select random recipients
                        recipients = random.sample(
                            WARMUP_RECIPIENTS, 
                            min(emails_to_send, len(WARMUP_RECIPIENTS))
                        )
                        
                        for recipient in recipients:
                            content_type = random.choice(list(EMAIL_CONTENT_TYPES.keys()))
                            
                            success = send_warmup_email(
                                campaign.id,
                                recipient['email'],
                                recipient['name'],
                                content_type
                            )
                            
                            logger.info(f"📨 Email to {recipient['email']}: {'✅' if success else '❌'}")
                            
                            # Delay between emails (shorter for demo accounts)
                            delay = random.uniform(5, 10) if user.is_demo() else random.uniform(30, 60)
                            time.sleep(delay)

        logger.info(f"✅ Processed {len(recipients)} emails for '{campaign.name}'")
                    else:
                        logger.info(f"⏭️ '{campaign.name}': Daily quota reached")
                        
                except Exception as e:
                    logger.error(f"Error processing campaign {campaign.id}: {str(e)}")
                    continue
    
    except Exception as e:
        logger.error(f"❌ Error processing warmup campaigns: {str(e)}")

def start_warmup_scheduler():
    """Start the background email scheduler with safe fallbacks"""
    def run_scheduler():
        logger.info("🚀 Warmup scheduler thread started")
        
        # Try to use the best available scheduler
        if SCHEDULE_AVAILABLE and schedule:
            logger.info("📅 Using schedule module for task scheduling")
            # Schedule email sending every 2 minutes for testing, every hour for production
            schedule.every(2).minutes.do(process_warmup_campaigns)
            
            while True:
                try:
                    schedule.run_pending()
                    time.sleep(60)
                except Exception as e:
                    logger.error(f"❌ Schedule error: {str(e)}")
                    time.sleep(60)
                    
        elif APSCHEDULER_AVAILABLE and scheduler:
            logger.info("📅 Using APScheduler for task scheduling")
            try:
                scheduler.add_job(
                    func=process_warmup_campaigns,
                    trigger="interval",
                    minutes=2,
                    id='warmup_processor'
                )
                logger.info("✅ APScheduler job added successfully")
                # Keep thread alive
                while True:
                    time.sleep(60)
            except Exception as e:
                logger.error(f"❌ APScheduler error: {str(e)}")
                
        else:
            logger.warning("⚠️ No scheduler available - using simple timer fallback")
            # Fallback: simple timer-based scheduling
            while True:
                try:
                    time.sleep(120)  # Wait 2 minutes
                    process_warmup_campaigns()
                except Exception as e:
                    logger.error(f"❌ Timer scheduler error: {str(e)}")
                    time.sleep(60)
    
    # Start scheduler in background thread
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    logger.info("⏰ Warmup scheduler started successfully")

# AUTHENTICATION ROUTES
@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/forgot-password')
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('forgot-password.html')

@app.route('/reset-password/<token>')
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Verify token
    reset_token = PasswordResetToken.query.filter_by(token=token, used=False).first()
    if not reset_token or reset_token.is_expired():
        flash('Invalid or expired reset token', 'error')
        return redirect(url_for('forgot_password'))
    
    return render_template('reset-password.html', token=token)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

# MAIN ROUTES
@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# *** ADD THIS NEW ROUTE ***
@app.route('/create-campaign')
@login_required
def create_campaign():
    """Campaign creation form page"""
    return render_template('create-campaign.html', providers=SMTP_PROVIDERS)

@app.route('/health')
def health_check():
    """Health check endpoint for Railway"""
    try:
        # Test database connection
        db.session.execute(db.text('SELECT 1'))
        db_status = 'connected'
    except Exception as e:
        db_status = f'error: {str(e)}'
        
    return jsonify({
        'status': 'healthy',
        'database': db_status,
        'scheduling': {
            'schedule_available': SCHEDULE_AVAILABLE,
            'apscheduler_available': APSCHEDULER_AVAILABLE,
            'scheduler_active': scheduler is not None
        },
        'timestamp': datetime.now().isoformat(),
        'version': '3.0.0'
    })

@app.route('/test')
def test_route():
    return jsonify({'status': 'working', 'timestamp': datetime.now().isoformat()})

@app.route('/debug/env')
def debug_env():
    """Debug environment variables to troubleshoot DATABASE_URL detection"""
    database_url = os.environ.get('DATABASE_URL', '')
    return jsonify({
        'DATABASE_URL_exists': bool(database_url),
        'DATABASE_URL_length': len(database_url),
        'DATABASE_URL_prefix': database_url[:50] + '...' if database_url else 'None',
        'starts_with_postgres': database_url.startswith('postgres') if database_url else False,
        'starts_with_postgresql': database_url.startswith('postgresql') if database_url else False,
        'contains_postgres': 'postgres' in database_url.lower() if database_url else False,
        'current_db_uri': app.config.get('SQLALCHEMY_DATABASE_URI', '')[:50] + '...',
        'all_env_vars': [k for k in os.environ.keys() if 'DATA' in k.upper() or 'POSTGRES' in k.upper()],
        'railway_vars': [k for k in os.environ.keys() if k.startswith('RAILWAY_')],
        'timestamp': datetime.now().isoformat()
    })
