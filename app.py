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
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
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

# ===========================================
# MULTI-ACCOUNT PROTONMAIL AUTO-REPLY INTEGRATION
# ===========================================

import imaplib
import email
import ssl

# Additional imports for ProtonMail integration
try:
    import openai
    OPENAI_AVAILABLE = True
    print("✅ OpenAI module loaded successfully")
except ImportError:
    OPENAI_AVAILABLE = False
    openai = None
    print("⚠️ OpenAI module not available - using fallback replies")

class MultiAccountProtonMailAutoReply:
    def __init__(self):
        self.imap_server = 'mail.protonmail.ch'
        self.smtp_server = 'mail.protonmail.ch'
        self.imap_port = 993
        self.smtp_port = 587
        
        # Configure OpenAI if available
        self.openai_api_key = os.environ.get('OPENAI_API_KEY')
        if OPENAI_AVAILABLE and self.openai_api_key:
            openai.api_key = self.openai_api_key
        
        # Load all email accounts
        self.accounts = []
        for i in range(1, 6):  # Accounts 1-5
            email_addr = os.environ.get(f'PROTONMAIL_EMAIL_{i}', '').strip()
            password = os.environ.get(f'PROTONMAIL_PASSWORD_{i}', '').strip()
            
            if email_addr and password:
                self.accounts.append({
                    'email': email_addr,
                    'password': password,
                    'processed_emails': set(),
                    'account_id': i
                })
        
        print(f"✅ Loaded {len(self.accounts)} ProtonMail accounts")
        
    def generate_ai_reply(self, original_subject, original_body, sender_email, account_email):
        """Generate AI reply using OpenAI"""
        try:
            if not OPENAI_AVAILABLE or not self.openai_api_key:
                return self.get_fallback_reply()
            
            prompt = f"""
            You are KEXY AI assistant replying from {account_email}. 
            
            Original email:
            From: {sender_email}
            Subject: {original_subject}
            Message: {original_body}
            
            Generate a professional, helpful reply. Keep it concise and friendly.
            Vary your response style slightly to seem more human.
            """
            
            response = openai.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=300,
                temperature=0.8  # Higher temperature for variety
            )
            
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(f"AI reply generation error: {e}")
            return self.get_fallback_reply()
    
    def get_fallback_reply(self):
        """Fallback replies if AI fails"""
        replies = [
            "Thank you for your email. I'll get back to you soon!",
            "Thanks for reaching out! I'll respond to your message shortly.",
            "I appreciate your email and will reply as soon as possible.",
            "Thank you for contacting me. I'll be in touch soon!",
            "Thanks for your message! I'll get back to you quickly.",
            "Great to hear from you! I'll respond to this shortly.",
            "I appreciate you reaching out. Will get back to you soon!",
            "Thanks for the email! I'll review this and respond quickly."
        ]
        return random.choice(replies)
    
    def send_reply(self, account, to_email, subject, body, original_message_id=None):
        """Send reply email from specific account"""
        try:
            msg = MIMEMultipart()
            msg['From'] = account['email']
            msg['To'] = to_email
            msg['Subject'] = f"Re: {subject}" if not subject.startswith('Re:') else subject
            
            if original_message_id:
                msg['In-Reply-To'] = original_message_id
                msg['References'] = original_message_id
            
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(account['email'], account['password'])
                server.send_message(msg)
            
            print(f"✅ Reply sent from {account['email']} to {to_email}")
            return True
        except Exception as e:
            print(f"❌ Failed to send reply from {account['email']}: {e}")
            return False
    
    def check_account_emails(self, account):
        """Check emails for a specific account"""
        try:
            with imaplib.IMAP4_SSL(self.imap_server, self.imap_port) as mail:
                mail.login(account['email'], account['password'])
                mail.select('INBOX')
                
                # Search for unread emails
                status, messages = mail.search(None, 'UNSEEN')
                email_ids = messages[0].split()
                
                for email_id in email_ids:
                    email_id_str = email_id.decode()
                    
                    if email_id_str in account['processed_emails']:
                        continue
                    
                    status, msg_data = mail.fetch(email_id, '(RFC822)')
                    email_message = email.message_from_bytes(msg_data[0][1])
                    
                    sender = email_message['From']
                    subject = email_message['Subject'] or 'No Subject'
                    message_id = email_message['Message-ID']
                    
                    # Skip if it's our own email or already a reply
                    if any(acc['email'] in sender for acc in self.accounts) or subject.startswith('Re:'):
                        account['processed_emails'].add(email_id_str)
                        continue
                    
                    # Get email body
                    body = ""
                    if email_message.is_multipart():
                        for part in email_message.walk():
                            if part.get_content_type() == "text/plain":
                                body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                break
                    else:
                        body = email_message.get_payload(decode=True).decode('utf-8', errors='ignore')
                    
                    # Generate and send AI reply
                    ai_reply = self.generate_ai_reply(subject, body, sender, account['email'])
                    
                    # Add random delay (1-5 minutes) to seem more human
                    delay = random.randint(60, 300)
                    time.sleep(delay)
                    
                    if self.send_reply(account, sender, subject, ai_reply, message_id):
                        account['processed_emails'].add(email_id_str)
                        
                        # Log to KEXY system
                        with app.app_context():
                            log_entry = f"Auto-reply sent from {account['email']} to {sender} - Subject: {subject}"
                            print(f"📧 KEXY Multi-Account: {log_entry}")
                    
        except Exception as e:
            print(f"❌ Email check error for {account['email']}: {e}")
    
    def monitor_account(self, account):
        """Monitor a specific account continuously"""
        while True:
            try:
                self.check_account_emails(account)
                # Random check interval (45-75 seconds) to avoid patterns
                check_interval = random.randint(45, 75)
                time.sleep(check_interval)
            except Exception as e:
                print(f"❌ Monitor error for {account['email']}: {e}")
                time.sleep(300)  # Wait 5 minutes on error
    
    def start_monitoring(self):
        """Start monitoring all accounts"""
        if not self.accounts:
            print("❌ No ProtonMail accounts configured")
            return
        
        for account in self.accounts:
            thread = threading.Thread(
                target=self.monitor_account, 
                args=(account,), 
                daemon=True,
                name=f"ProtonMail-{account['account_id']}"
            )
            thread.start()
            print(f"✅ Started monitoring {account['email']}")
        
        print(f"🚀 ProtonMail multi-account monitoring started for {len(self.accounts)} accounts")

# Initialize Multi-Account ProtonMail auto-reply
protonmail_multi_reply = MultiAccountProtonMailAutoReply()

# Test endpoint for multi-account system
@app.route('/test-multi-email')
@login_required
def test_multi_email():
    """Test endpoint to check all email accounts"""
    results = []
    
    for account in protonmail_multi_reply.accounts:
        try:
            protonmail_multi_reply.check_account_emails(account)
            results.append({
                'account': account['email'],
                'status': 'success',
                'message': 'Email check completed'
            })
        except Exception as e:
            results.append({
                'account': account['email'],
                'status': 'error',
                'message': str(e)
            })
    
    return jsonify({
        'status': 'completed',
        'results': results,
        'total_accounts': len(protonmail_multi_reply.accounts),
        'timestamp': datetime.now().isoformat()
    })

# AUTO-CREATE DATABASE TABLES ON STARTUP (Railway-friendly)
def init_database():
    """Initialize database tables and demo data"""
    try:
        with app.app_context():
            # Create all tables
            db.create_all()
            logger.info("✅ Database tables created successfully")
            
            # Create demo user if it doesn't exist
            create_demo_user()
            
            # Create initial recipients
            create_initial_recipients()
            
            logger.info("✅ Database initialization complete")
            
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {str(e)}")

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

# Fallback Recipients Pool (for initial setup/testing)
FALLBACK_RECIPIENTS = [
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
    recipients = db.relationship('Recipient', backref='user', lazy=True, cascade='all, delete-orphan')

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
    campaign_recipients = db.relationship('CampaignRecipient', backref='campaign', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        recipient_count = CampaignRecipient.query.filter_by(campaign_id=self.id).count()
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
            'user_id': self.user_id,
            'recipient_count': recipient_count
        }

    def __repr__(self):
        return f'<Campaign {self.name}>'

class Recipient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(50), default='General')
    status = db.Column(db.String(20), default='active')  # active, inactive
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    campaign_recipients = db.relationship('CampaignRecipient', backref='recipient', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'category': self.category,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'user_id': self.user_id
        }

    def __repr__(self):
        return f'<Recipient {self.email}>'

class CampaignRecipient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('recipient.id'), nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    emails_sent = db.Column(db.Integer, default=0)
    last_emailed = db.Column(db.DateTime)

    __table_args__ = (db.UniqueConstraint('campaign_id', 'recipient_id', name='unique_campaign_recipient'),)

    def to_dict(self):
        return {
            'id': self.id,
            'campaign_id': self.campaign_id,
            'recipient_id': self.recipient_id,
            'assigned_at': self.assigned_at.isoformat() if self.assigned_at else None,
            'emails_sent': self.emails_sent,
            'last_emailed': self.last_emailed.isoformat() if self.last_emailed else None
        }

    def __repr__(self):
        return f'<CampaignRecipient {self.campaign_id}-{self.recipient_id}>'

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

# NEW: Database-Driven Recipients Model (keeping for backward compatibility)
class WarmupRecipient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    name = db.Column(db.String(100), nullable=False)
    industry = db.Column(db.String(50), default='business')
    responds = db.Column(db.Boolean, default=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_emailed = db.Column(db.DateTime)
    email_count = db.Column(db.Integer, default=0)
    success_rate = db.Column(db.Float, default=0.0)
    notes = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'industry': self.industry,
            'responds': self.responds,
            'is_active': self.is_active,
            'email_count': self.email_count,
            'success_rate': round(self.success_rate, 1),
            'last_emailed': self.last_emailed.isoformat() if self.last_emailed else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'notes': self.notes
        }

    def update_stats(self, success=True):
        """Update recipient statistics after sending email"""
        self.email_count += 1
        self.last_emailed = datetime.utcnow()
        
        # Calculate success rate (simplified)
        if success:
            self.success_rate = ((self.success_rate * (self.email_count - 1)) + 100) / self.email_count
        else:
            self.success_rate = (self.success_rate * (self.email_count - 1)) / self.email_count

    def __repr__(self):
        return f'<WarmupRecipient {self.email}>'

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

# Template Helper Functions
def template_exists(template_name):
    """Check if a template file exists"""
    try:
        app.jinja_env.get_template(template_name)
        return True
    except:
        return False

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

def create_initial_recipients():
    """Create initial recipient pool from fallback list"""
    try:
        existing_count = WarmupRecipient.query.count()
        if existing_count == 0:
            logger.info("Creating initial recipient pool...")
            
            for recipient_data in FALLBACK_RECIPIENTS:
                recipient = WarmupRecipient(
                    email=recipient_data['email'],
                    name=recipient_data['name'],
                    industry=recipient_data['industry'],
                    responds=recipient_data['responds']
                )
                db.session.add(recipient)
            
            db.session.commit()
            logger.info(f"Created {len(FALLBACK_RECIPIENTS)} initial recipients")
            
        return True
    except Exception as e:
        logger.error(f"Failed to create initial recipients: {str(e)}")
        return False

# ✅ FIXED: Enhanced Recipient Management Functions - ONLY USER'S REAL RECIPIENTS
def get_campaign_recipients(campaign_id, count=10):
    """Get recipients assigned to a specific campaign - ONLY USER'S REAL RECIPIENTS"""
    try:
        # Get assigned recipients for this campaign (USER'S RECIPIENTS ONLY)
        campaign_recipients = db.session.query(Recipient)\
            .join(CampaignRecipient)\
            .filter(CampaignRecipient.campaign_id == campaign_id)\
            .filter(Recipient.status == 'active')\
            .order_by(CampaignRecipient.last_emailed.asc().nullsfirst())\
            .limit(count).all()
        
        recipient_list = []
        for r in campaign_recipients:
            recipient_list.append({
                'id': r.id,
                'email': r.email,
                'name': r.name,
                'category': r.category,
                'responds': True
            })
        
        # ✅ FIXED: NO FALLBACK TO FAKE RECIPIENTS
        logger.info(f"Found {len(recipient_list)} real recipients for campaign {campaign_id}")
        return recipient_list
        
    except Exception as e:
        logger.error(f"Error getting campaign recipients: {str(e)}")
        return []  # Return empty list instead of fake recipients

def get_warmup_recipients(count=10, industry_filter=None, exclude_recently_emailed=True):
    """Get warmup recipients from database with intelligent selection"""
    try:
        # Start with active recipients
        query = WarmupRecipient.query.filter_by(is_active=True)
        
        # Filter by industry if specified
        if industry_filter:
            query = query.filter(WarmupRecipient.industry == industry_filter)
        
        # Exclude recently emailed recipients (within last 24 hours)
        if exclude_recently_emailed:
            yesterday = datetime.utcnow() - timedelta(hours=24)
            query = query.filter(
                db.or_(
                    WarmupRecipient.last_emailed.is_(None),
                    WarmupRecipient.last_emailed < yesterday
                )
            )
        
        # Order by least recently emailed, then by email count (load balancing)
        query = query.order_by(
            WarmupRecipient.last_emailed.asc().nullsfirst(),
            WarmupRecipient.email_count.asc()
        )
        
        recipients = query.limit(count).all()
        
        # Convert to the format expected by the warmup process
        recipient_list = []
        for r in recipients:
            recipient_list.append({
                'id': r.id,
                'email': r.email,
                'name': r.name,
                'industry': r.industry,
                'responds': r.responds
            })

        # If we don't have enough recipients, fall back to the hardcoded list
        if len(recipient_list) < count:
            logger.warning(f"Only found {len(recipient_list)} recipients in database, falling back to hardcoded list")
            fallback_needed = count - len(recipient_list)
            fallback_recipients = random.sample(
                FALLBACK_RECIPIENTS, 
                min(fallback_needed, len(FALLBACK_RECIPIENTS))
            )
            
            for fb_recipient in fallback_recipients:
                recipient_list.append({
                    'id': None,  # Mark as fallback
                    'email': fb_recipient['email'],
                    'name': fb_recipient['name'],
                    'industry': fb_recipient['industry'],
                    'responds': fb_recipient['responds']
                })
        
        return recipient_list[:count]
        
    except Exception as e:
        logger.error(f"Error getting warmup recipients: {str(e)}")
        # Fallback to hardcoded list
        return random.sample(FALLBACK_RECIPIENTS, min(count, len(FALLBACK_RECIPIENTS)))

def update_recipient_stats(recipient_email, success=True):
    """Update recipient statistics after sending email"""
    try:
        recipient = WarmupRecipient.query.filter_by(email=recipient_email).first()
        if recipient:
            recipient.update_stats(success)
            db.session.commit()
    except Exception as e:
        logger.error(f"Error updating recipient stats: {str(e)}")

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
def send_warmup_email(campaign_id, recipient_data, content_type):
    """Send warmup email with enhanced error handling and recipient tracking"""
    try:
        with app.app_context():
            campaign = db.session.get(Campaign, campaign_id)
            if not campaign or campaign.status != 'active':
                logger.error(f"Campaign {campaign_id} not active or not found")
                return False
            
            recipient_email = recipient_data['email']
            recipient_name = recipient_data['name']
            recipient_id = recipient_data.get('id')  # Database ID or None for fallback
            
            # Check if user is demo (demo campaigns don't actually send emails)
            user = db.session.get(User, campaign.user_id)
            if user and user.is_demo():
                logger.info(f"Demo campaign {campaign_id} - simulated email send to {recipient_email}")
                log_email(campaign_id, recipient_email, "Demo Email", 'sent')
                campaign.emails_sent += 1
                update_campaign_success_rate(campaign_id)

                # Update recipient stats if it's a database recipient
                if recipient_id:
                    update_recipient_stats(recipient_email, success=True)
                
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
            
            # Update recipient stats if it's a database recipient
            if recipient_id:
                update_recipient_stats(recipient_email, success=True)
            
            db.session.commit()
            logger.info(f"Email sent successfully to {recipient_email}")
        else:
            # Update recipient stats for failed send if it's a database recipient
            if recipient_id:
                update_recipient_stats(recipient_email, success=False)
            db.session.commit()
            
        return success
    
    except Exception as e:
        logger.error(f"Error sending warmup email: {str(e)}")
        with app.app_context():
            log_email(campaign_id, recipient_data['email'], "Error", 'failed', str(e))
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

# ✅ FIXED: Background Scheduler Functions - ONLY USER'S REAL RECIPIENTS
def process_warmup_campaigns():
    """Process all active campaigns for email sending with enhanced recipient management"""
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
                        # Get recipients using the new intelligent selection - ONLY USER'S REAL RECIPIENTS
                        recipients = get_campaign_recipients(
                            campaign.id,
                            count=emails_to_send
                        )
                        
                        # ✅ FIXED: NO FALLBACK TO FAKE RECIPIENTS
                        if not recipients:
                            logger.info(f"⏭️ Skipping campaign '{campaign.name}': No recipients assigned")
                            continue
                        
                        logger.info(f"📋 Selected {len(recipients)} recipients for '{campaign.name}'")
                        
                        for recipient in recipients:
                            content_type = random.choice(list(EMAIL_CONTENT_TYPES.keys()))
                            
                            success = send_warmup_email(
                                campaign.id,
                                recipient,
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
    # Force session clear on login page access after logout - MUST BE FIRST
    if request.args.get('logout') == 'true':
        session.clear()
        # Force logout any remaining user session
        if current_user.is_authenticated:
            logout_user()
    
    # Now check authentication after potential session clear
    if current_user.is_authenticated:
        try:
            # Double-check if user is really authenticated
            if current_user.is_active:
                return redirect(url_for('dashboard'))
        except:
            # If there's an issue with user authentication, clear session
            session.clear()
            logout_user()
    
    return render_template('login.html')

@app.route('/register')
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('register.html')

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
    return render_template('profile.html', form=None)

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

@app.route('/create-campaign')
@login_required
def create_campaign():
    """Campaign creation form page"""
    return render_template('create-campaign.html', providers=SMTP_PROVIDERS)

@app.route('/campaigns')
@login_required
def campaigns_page():
    """Campaigns list page"""
    return render_template('campaigns.html')

@app.route('/recipients')
@login_required
def recipients_page():
    """Recipients management page"""
    return render_template('recipients.html')

@app.route('/health')
def health_check():
    """Health check endpoint for Railway"""
    try:
        # Test database connection
        db.session.execute(db.text('SELECT 1'))
        db_status = 'connected'
        
        # Check recipient count
        recipient_count = WarmupRecipient.query.count()
        
    except Exception as e:
        db_status = f'error: {str(e)}'
        recipient_count = 0
        
    return jsonify({
        'status': 'healthy',
        'database': db_status,
        'recipients': {
            'count': recipient_count,
            'active': WarmupRecipient.query.filter_by(is_active=True).count() if db_status == 'connected' else 0
        },
        'scheduling': {
            'schedule_available': SCHEDULE_AVAILABLE,
            'apscheduler_available': APSCHEDULER_AVAILABLE,
            'scheduler_active': scheduler is not None
        },
        'timestamp': datetime.now().isoformat(),
        'version': '3.1.0'
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

# AUTHENTICATION API ROUTES
@app.route('/api/auth/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        remember = data.get('remember', False)
        
        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password are required'}), 400
        
        user = User.query.filter_by(email=email).first()

# Log login attempt
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        if user and user.check_password(password) and user.is_active:
            # Successful login
            log_login_attempt(email, ip_address, True)
            
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            login_user(user, remember=remember)
            session.permanent = remember
            
            logger.info(f"User {user.username} logged in successfully")
            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'user': user.to_dict(),
                'redirect_url': url_for('dashboard')
            })
        else:
            # Failed login
            log_login_attempt(email, ip_address, False)
            
            return jsonify({
                'success': False,
                'message': 'Invalid email or password'
            }), 401
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'success': False, 'message': 'Login failed'}), 500

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        # Validation
        if not username or not email or not password:
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        if len(password) < 8:
            return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already registered'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already taken'}), 400
        
        # Create new user
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role='user',
            email_verified=True  # Skip email verification for now
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Auto-login
        login_user(user)
        
        logger.info(f"New user registered: {username}")
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'user': user.to_dict(),
            'redirect_url': url_for('dashboard')
        })
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Registration failed'}), 500

@app.route('/api/auth/demo-login', methods=['POST'])
def api_demo_login():
    try:
        demo_user = User.query.filter_by(role='demo').first()
        if not demo_user:
            demo_user = create_demo_user()
        
        if demo_user:
            login_user(demo_user)
            logger.info("Demo user logged in")
            
            return jsonify({
                'success': True,
                'message': 'Demo login successful',
                'user': demo_user.to_dict(),
                'redirect_url': url_for('dashboard')
            })
        else:
            return jsonify({'success': False, 'message': 'Demo account unavailable'}), 500
            
    except Exception as e:
        logger.error(f"Demo login error: {str(e)}")
        return jsonify({'success': False, 'message': 'Demo login failed'}), 500

@app.route('/api/auth/forgot-password', methods=['POST'])
def api_forgot_password():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'success': False, 'message': 'Email is required'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate reset token
            token = generate_reset_token()
            expires_at = datetime.utcnow() + timedelta(hours=1)
            
            reset_token = PasswordResetToken(
                user_id=user.id,
                token=token,
                expires_at=expires_at
            )
            
            db.session.add(reset_token)
            db.session.commit()
            
            # Send reset email
            if send_reset_email(user, token):
                return jsonify({
                    'success': True,
                    'message': 'Password reset email sent'
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Failed to send reset email'
                }), 500
        else:
            # Don't reveal if email exists
            return jsonify({
                'success': True,
                'message': 'If the email exists, a reset link will be sent'
            })
            
    except Exception as e:
        logger.error(f"Forgot password error: {str(e)}")
        return jsonify({'success': False, 'message': 'Request failed'}), 500

@app.route('/api/auth/reset-password', methods=['POST'])
def api_reset_password():
    try:
        data = request.get_json()
        token = data.get('token', '')
        new_password = data.get('password', '')
        
        if not token or not new_password:
            return jsonify({'success': False, 'message': 'Token and password are required'}), 400
        
        if len(new_password) < 8:
            return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400
        
        # Verify token
        reset_token = PasswordResetToken.query.filter_by(token=token, used=False).first()
        
        if not reset_token or reset_token.is_expired():
            return jsonify({'success': False, 'message': 'Invalid or expired token'}), 400
        
        # Update password
        user = db.session.get(User, reset_token.user_id)
        user.password_hash = generate_password_hash(new_password)
        
        # Mark token as used
        reset_token.used = True
        
        db.session.commit()
        
        logger.info(f"Password reset successful for user {user.username}")
        
        return jsonify({
            'success': True,
            'message': 'Password reset successful',
            'redirect_url': url_for('login')
        })
        
    except Exception as e:
        logger.error(f"Reset password error: {str(e)}")
        return jsonify({'success': False, 'message': 'Password reset failed'}), 500

@app.route('/api/auth/logout', methods=['POST', 'GET'])
@login_required
def api_logout():
    try:
        username = current_user.username
        logout_user()
        session.clear()
        
        logger.info(f"User {username} logged out")
        
        # For GET requests (direct browser access), redirect immediately
        if request.method == 'GET':
            return redirect(url_for('login', logout='true'))
        
        # For POST requests (AJAX), return JSON
        return jsonify({
            'success': True,
            'message': 'Logout successful',
            'redirect_url': url_for('login')
        })
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        # Always redirect to login on error for GET requests
        if request.method == 'GET':
            return redirect(url_for('login', logout='true'))
        else:
            return jsonify({'success': False, 'message': 'Logout failed'}), 500

@app.route('/api/auth/user')
@login_required
def api_current_user():
    return jsonify({
        'success': True,
        'user': current_user.to_dict()
    })

@app.route('/api/auth/update-profile', methods=['PUT'])
@login_required
def api_update_profile():
    try:
        data = request.get_json()
        
        # Update allowed fields
        if 'username' in data and data['username'].strip():
            new_username = data['username'].strip()
            if new_username != current_user.username:
                if User.query.filter_by(username=new_username).first():
                    return jsonify({'success': False, 'message': 'Username already taken'}), 400
                current_user.username = new_username
        
        if 'email' in data and data['email'].strip():
            new_email = data['email'].strip().lower()
            if new_email != current_user.email:
                if User.query.filter_by(email=new_email).first():
                    return jsonify({'success': False, 'message': 'Email already registered'}), 400
                current_user.email = new_email
                current_user.email_verified = False  # Require re-verification
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Profile updated successfully',
            'user': current_user.to_dict()
        })
        
    except Exception as e:
        logger.error(f"Profile update error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Profile update failed'}), 500

@app.route('/api/auth/change-password', methods=['POST'])
@login_required
def api_change_password():
    try:
        data = request.get_json()
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        
        if not current_password or not new_password:
            return jsonify({'success': False, 'message': 'Current and new passwords are required'}), 400
        
        if not current_user.check_password(current_password):
            return jsonify({'success': False, 'message': 'Current password is incorrect'}), 400
        
        if len(new_password) < 8:
            return jsonify({'success': False, 'message': 'New password must be at least 8 characters'}), 400
        
        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Password changed successfully'
        })
        
    except Exception as e:
        logger.error(f"Change password error: {str(e)}")
        return jsonify({'success': False, 'message': 'Password change failed'}), 500

# NEW: RECIPIENT MANAGEMENT API ROUTES
@app.route('/api/recipients', methods=['GET', 'POST'])
@login_required
def manage_recipients():
    if request.method == 'GET':
        try:
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 50, type=int)
            search = request.args.get('search', '').strip()
            category_filter = request.args.get('category', '').strip()
            
            # ✅ FIXED: Get the actual status parameter from frontend
            status_filter = request.args.get('status', '').strip()
            active_only = request.args.get('active_only', 'false').lower() == 'true'

            # Build query - users can only see their own recipients
            query = Recipient.query.filter_by(user_id=current_user.id)
            
            if active_only:
                query = query.filter_by(status='active')
            
            if search:
                query = query.filter(
                    db.or_(
                        Recipient.email.ilike(f'%{search}%'),
                        Recipient.name.ilike(f'%{search}%')
                    )
                )
            
            if category_filter:
                query = query.filter_by(category=category_filter)
                
            # Order by most recently created
            query = query.order_by(Recipient.created_at.desc())
                
            # Paginate
            recipients = query.paginate(page=page, per_page=per_page, error_out=False)
            
            # Get category list for filter dropdown
            categories = db.session.query(Recipient.category).filter_by(user_id=current_user.id).distinct().all()
            category_list = [c[0] for c in categories if c[0]]
            
            return jsonify({
                'recipients': [r.to_dict() for r in recipients.items],
                'pagination': {
                    'page': recipients.page,
                    'pages': recipients.pages,
                    'per_page': recipients.per_page,
                    'total': recipients.total,
                    'has_next': recipients.has_next,
                    'has_prev': recipients.has_prev
                },
                'categories': sorted(category_list),
                'total_count': Recipient.query.filter_by(user_id=current_user.id).count(),
                'active_count': Recipient.query.filter_by(user_id=current_user.id, status='active').count(),
                'filtered_count': recipients.total
            })
            
        except Exception as e:
            logger.error(f"Error fetching recipients: {str(e)}")
            return jsonify({'error': 'Failed to fetch recipients'}), 500
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            
            # Validate required fields
            if not data.get('email') or not data.get('name'):
                return jsonify({'success': False, 'message': 'Email and name are required'}), 400
            
            # Check if email already exists for this user
            existing = Recipient.query.filter_by(
                email=data['email'].strip().lower(),
                user_id=current_user.id
            ).first()
            if existing:
                return jsonify({'success': False, 'message': 'Email already exists in your recipients'}), 400
            
            # Create new recipient
            recipient = Recipient(
                email=data['email'].strip().lower(),
                name=data['name'].strip(),
                category=data.get('category', 'General').strip(),
                status=data.get('status', 'active'),
                user_id=current_user.id
            )
            
            db.session.add(recipient)
            db.session.commit()
            
            logger.info(f"New recipient added by {current_user.username}: {recipient.email}")
            
            return jsonify({
                'success': True,
                'message': 'Recipient added successfully',
                'recipient': recipient.to_dict()
            })
            
        except Exception as e:
            logger.error(f"Error adding recipient: {str(e)}")
            db.session.rollback()
            return jsonify({'success': False, 'message': 'Failed to add recipient'}), 500

@app.route('/api/recipients/stats')
@login_required
def recipient_stats():
    """Get recipient statistics"""
    try:
        if current_user.is_admin():
            total_recipients = Recipient.query.count() + WarmupRecipient.query.count()
            active_recipients = Recipient.query.filter_by(status='active').count() + WarmupRecipient.query.filter_by(is_active=True).count()
        else:
            total_recipients = Recipient.query.filter_by(user_id=current_user.id).count()
            active_recipients = Recipient.query.filter_by(user_id=current_user.id, status='active').count()
        
        return jsonify({
            'total_recipients': total_recipients,
            'active_recipients': active_recipients,
            'inactive_recipients': total_recipients - active_recipients,
            'recently_emailed': 0,
            'average_success_rate': 0
        })
        
    except Exception as e:
        logger.error(f"Recipient stats error: {str(e)}")
        return jsonify({
            'total_recipients': 0,
            'active_recipients': 0,
            'inactive_recipients': 0,
            'recently_emailed': 0,
            'average_success_rate': 0
        })

@app.route('/api/recipients/<int:recipient_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def recipient_detail(recipient_id):
    try:
        recipient = db.session.get(Recipient, recipient_id)
        if not recipient or recipient.user_id != current_user.id:
            return jsonify({'error': 'Recipient not found'}), 404
        
        if request.method == 'GET':
            return jsonify(recipient.to_dict())
        
        elif request.method == 'PUT':
            data = request.get_json()

            # Update allowed fields
            if 'name' in data:
                recipient.name = data['name'].strip()
            if 'category' in data:
                recipient.category = data['category'].strip()
            if 'status' in data:
                recipient.status = data['status']
            
            recipient.updated_at = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Recipient updated successfully',
                'recipient': recipient.to_dict()
            })
        
        elif request.method == 'DELETE':
            db.session.delete(recipient)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Recipient deleted successfully'
            })
            
    except Exception as e:
        logger.error(f"Recipient detail error: {str(e)}")
        return jsonify({'success': False, 'message': 'Operation failed'}), 500

@app.route('/api/recipients/<int:recipient_id>/toggle-status', methods=['POST'])
@login_required
def toggle_recipient_status(recipient_id):
    try:
        recipient = db.session.get(Recipient, recipient_id)
        if not recipient or recipient.user_id != current_user.id:
            return jsonify({'error': 'Recipient not found'}), 404
        
        # Toggle status
        recipient.status = 'inactive' if recipient.status == 'active' else 'active'
        recipient.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Recipient status updated to {recipient.status}',
            'recipient': recipient.to_dict()
        })
        
    except Exception as e:
        logger.error(f"Toggle recipient status error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to update status'}), 500

@app.route('/api/recipients/bulk-import', methods=['POST'])
@login_required
def bulk_import_recipients():
    """Bulk import recipients from file upload"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        if not file.filename.endswith('.csv'):
            return jsonify({'success': False, 'message': 'Only CSV files are supported'}), 400
        
        # Read CSV content
        import csv
        import io
        
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_input = csv.reader(stream)
        
        added_count = 0
        skipped_count = 0
        errors = []
        
        # Skip header row if present
        headers = next(csv_input, None)
        if headers and any(header.lower() in ['name', 'email', 'category'] for header in headers):
            # Headers detected, continue processing
            pass
        else:
            # No headers, treat first row as data
            stream.seek(0)
            csv_input = csv.reader(stream)
        
        for row_num, row in enumerate(csv_input, start=2):
            try:
                if len(row) < 2:
                    errors.append(f"Row {row_num}: Insufficient data (need at least name and email)")
                    skipped_count += 1
                    continue
                
                name = row[0].strip() if len(row) > 0 else ''
                email = row[1].strip().lower() if len(row) > 1 else ''
                category = row[2].strip() if len(row) > 2 else 'General'
                
                if not name or not email:
                    errors.append(f"Row {row_num}: Missing name or email")
                    skipped_count += 1
                    continue
                
                # Check if already exists for this user
                existing = Recipient.query.filter_by(email=email, user_id=current_user.id).first()
                if existing:
                    errors.append(f"Row {row_num}: {email} already exists")
                    skipped_count += 1
                    continue
                
                # Create recipient
                recipient = Recipient(
                    name=name,
                    email=email,
                    category=category,
                    status='active',
                    user_id=current_user.id
                )
                
                db.session.add(recipient)
                added_count += 1
                
            except Exception as e:
                errors.append(f"Row {row_num}: {str(e)}")
                skipped_count += 1
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Import completed: {added_count} added, {skipped_count} skipped',
            'imported_count': added_count,
            'skipped_count': skipped_count,
            'errors': errors[:10]  # Limit errors shown
        })
        
    except Exception as e:
        logger.error(f"Bulk import recipients error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Import failed'}), 500

# CAMPAIGN-RECIPIENTS MANAGEMENT API ROUTES
@app.route('/api/campaigns/<int:campaign_id>/recipients', methods=['GET', 'POST'])
@login_required
def campaign_recipients(campaign_id):
    try:
        campaign = db.session.get(Campaign, campaign_id)
        if not campaign or campaign.user_id != current_user.id:
            return jsonify({'error': 'Campaign not found'}), 404
        
        if request.method == 'GET':
            # Get recipients assigned to this campaign
            assigned_recipients = db.session.query(Recipient)\
                .join(CampaignRecipient)\
                .filter(CampaignRecipient.campaign_id == campaign_id)\
                .all()
            
            return jsonify([r.to_dict() for r in assigned_recipients])
        
        elif request.method == 'POST':
            data = request.get_json()
            recipient_id = data.get('recipient_id')
            
            if not recipient_id:
                return jsonify({'success': False, 'message': 'Recipient ID required'}), 400
            
            # Verify recipient belongs to current user
            recipient = db.session.get(Recipient, recipient_id)
            if not recipient or recipient.user_id != current_user.id:
                return jsonify({'success': False, 'message': 'Recipient not found'}), 404
            
            # Check if already assigned
            existing = CampaignRecipient.query.filter_by(
                campaign_id=campaign_id,
                recipient_id=recipient_id
            ).first()
            
            if existing:
                return jsonify({'success': False, 'message': 'Recipient already assigned to campaign'}), 400
            
            # Create assignment
            assignment = CampaignRecipient(
                campaign_id=campaign_id,
                recipient_id=recipient_id
            )
            
            db.session.add(assignment)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Recipient assigned to campaign successfully'
            })
            
    except Exception as e:
        logger.error(f"Campaign recipients error: {str(e)}")
        return jsonify({'success': False, 'message': 'Operation failed'}), 500

@app.route('/api/campaigns/<int:campaign_id>/recipients/<int:recipient_id>', methods=['DELETE'])
@login_required
def remove_campaign_recipient(campaign_id, recipient_id):
    try:
        campaign = db.session.get(Campaign, campaign_id)
        if not campaign or campaign.user_id != current_user.id:
            return jsonify({'error': 'Campaign not found'}), 404
        
        # Find assignment
        assignment = CampaignRecipient.query.filter_by(
            campaign_id=campaign_id,
            recipient_id=recipient_id
        ).first()
        
        if not assignment:
            return jsonify({'success': False, 'message': 'Assignment not found'}), 404
        
        db.session.delete(assignment)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Recipient removed from campaign successfully'
        })
        
    except Exception as e:
        logger.error(f"Remove campaign recipient error: {str(e)}")
        return jsonify({'success': False, 'message': 'Operation failed'}), 500

@app.route('/api/campaigns/<int:campaign_id>/recipients/assign-all', methods=['POST'])
@login_required
def assign_all_recipients(campaign_id):
    try:
        campaign = db.session.get(Campaign, campaign_id)
        if not campaign or campaign.user_id != current_user.id:
            return jsonify({'error': 'Campaign not found'}), 404
        
        # Get all active recipients for this user
        active_recipients = Recipient.query.filter_by(
            user_id=current_user.id,
            status='active'
        ).all()
        
        # Get already assigned recipient IDs
        assigned_ids = db.session.query(CampaignRecipient.recipient_id)\
            .filter_by(campaign_id=campaign_id)\
            .all()
        assigned_ids = [id[0] for id in assigned_ids]
        
        # Assign unassigned recipients
        new_assignments = 0
        for recipient in active_recipients:
            if recipient.id not in assigned_ids:
                assignment = CampaignRecipient(
                    campaign_id=campaign_id,
                    recipient_id=recipient.id
                )
                db.session.add(assignment)
                new_assignments += 1
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Assigned {new_assignments} recipients to campaign',
            'count': new_assignments
        })
        
    except Exception as e:
        logger.error(f"Assign all recipients error: {str(e)}")
        return jsonify({'success': False, 'message': 'Operation failed'}), 500

# API ROUTES (Enhanced with user awareness)
@app.route('/api/dashboard-stats')
@login_required
def dashboard_stats():
    try:
        if current_user.is_admin():
            # Admin sees all stats
            total_campaigns = Campaign.query.count()
            active_campaigns = Campaign.query.filter_by(status='active').count()
            successful_emails = EmailLog.query.filter_by(status='sent').count()
            total_emails = EmailLog.query.count()
            total_recipients = WarmupRecipient.query.count()
        else:
            # Users see only their stats
            user_campaigns = Campaign.query.filter_by(user_id=current_user.id)
            campaign_ids = [c.id for c in user_campaigns]
            
            total_campaigns = user_campaigns.count()
            active_campaigns = user_campaigns.filter_by(status='active').count()
            total_recipients = Recipient.query.filter_by(user_id=current_user.id, status='active').count()
            
            if campaign_ids:
                successful_emails = EmailLog.query.filter(
                    EmailLog.campaign_id.in_(campaign_ids),
                    EmailLog.status == 'sent'
                ).count()
                total_emails = EmailLog.query.filter(
                    EmailLog.campaign_id.in_(campaign_ids)
                ).count()
            else:
                successful_emails = 0
                total_emails = 0
        
        success_rate = (successful_emails / total_emails * 100) if total_emails > 0 else 0
        
        return jsonify({
            'total_campaigns': total_campaigns,
            'active_campaigns': active_campaigns,
            'emails_sent': successful_emails,
            'success_rate': round(success_rate, 1),
            'total_recipients': total_recipients
        })
    except Exception as e:
        logger.error(f"Dashboard stats error: {str(e)}")
        return jsonify({
            'total_campaigns': 0,
            'active_campaigns': 0,
            'emails_sent': 0,
            'success_rate': 0.0,
            'total_recipients': 0
        })

@app.route('/api/campaigns', methods=['GET', 'POST'])
@login_required
def campaigns():
    if request.method == 'GET':
        try:
            if current_user.is_admin():
                # Admin sees all campaigns
                all_campaigns = Campaign.query.all()
            else:
                # Users see only their campaigns
                all_campaigns = Campaign.query.filter_by(user_id=current_user.id).all()
            
            return jsonify([campaign.to_dict() for campaign in all_campaigns])
        except Exception as e:
            logger.error(f"Error fetching campaigns: {str(e)}")
            return jsonify([])

    elif request.method == 'POST':
        try:
            # Check campaign limit
            user_campaign_count = Campaign.query.filter_by(user_id=current_user.id).count()
            if user_campaign_count >= current_user.get_campaign_limit():
                return jsonify({
                    'success': False, 
                    'message': f'Campaign limit reached. {current_user.role.title()} accounts can have {current_user.get_campaign_limit()} campaigns.'
                }), 400

            data = request.get_json()
            
            # Validate required fields
            required_fields = ['name', 'email', 'provider', 'username', 'password']
            if not all(field in data for field in required_fields):
                return jsonify({'success': False, 'message': 'Missing required fields'}), 400

            # Validate provider
            provider = data['provider']
            if provider not in SMTP_PROVIDERS:
                return jsonify({'success': False, 'message': 'Invalid provider'}), 400

# Create campaign for current user
            campaign = Campaign(
                name=data['name'],
                email=data['email'],
                provider=provider,
                smtp_host=SMTP_PROVIDERS[provider]['host'],
                smtp_port=SMTP_PROVIDERS[provider]['port'],
                smtp_username=data['username'],
                smtp_password=data['password'],
                industry=data.get('industry', 'business'),
                daily_volume=int(data.get('daily_volume', 10)),
                warmup_days=int(data.get('warmup_days', 30)),
                user_id=current_user.id
            )

            db.session.add(campaign)
            db.session.commit()

            # ✅ FIXED: Check if user has any active recipients
            user_recipients_count = Recipient.query.filter_by(user_id=current_user.id, status='active').count()

            logger.info(f"Campaign created: {campaign.name} for user {current_user.username}")

            if user_recipients_count == 0:
                return jsonify({
                    'success': True, 
                    'message': 'Campaign created successfully! Please assign recipients to start sending emails.',
                    'campaign': campaign.to_dict(),
                    'requires_recipients': True,
                    'redirect_to_recipients': True
                })
            else:
                return jsonify({
                    'success': True, 
                    'message': 'Campaign created successfully', 
                    'campaign': campaign.to_dict(),
                    'requires_recipients': False
                })

        except Exception as e:
            logger.error(f"Campaign creation error: {str(e)}")
            db.session.rollback()
            return jsonify({'success': False, 'message': f'Failed to create campaign: {str(e)}'}), 500

@app.route('/api/campaigns/<int:campaign_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def campaign_detail(campaign_id):
    try:
        campaign = db.session.get(Campaign, campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404

        # Check ownership (non-admin users can only access their campaigns)
        if not current_user.is_admin() and campaign.user_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403

        if request.method == 'GET':
            return jsonify(campaign.to_dict())

        elif request.method == 'PUT':
            # Demo users cannot modify campaigns
            if current_user.is_demo():
                return jsonify({'error': 'Demo accounts cannot modify campaigns'}), 403
                
            data = request.get_json()
            updateable_fields = ['name', 'daily_volume', 'warmup_days', 'industry']
            for field in updateable_fields:
                if field in data:
                    setattr(campaign, field, data[field])
            
            campaign.updated_at = datetime.utcnow()
            db.session.commit()
            return jsonify({'success': True, 'message': 'Campaign updated', 'campaign': campaign.to_dict()})

        elif request.method == 'DELETE':
            # Demo users cannot delete campaigns
            if current_user.is_demo():
                return jsonify({'error': 'Demo accounts cannot delete campaigns'}), 403
            
            try:
                campaign_id = campaign.id
                campaign_name = campaign.name
                
                # Manually delete related records first to avoid foreign key constraints
                EmailLog.query.filter_by(campaign_id=campaign_id).delete()
                CampaignRecipient.query.filter_by(campaign_id=campaign_id).delete()
                
                # Now delete the campaign
                db.session.delete(campaign)
                db.session.commit()
                
                logger.info(f"Campaign '{campaign_name}' (ID: {campaign_id}) deleted successfully by user {current_user.username}")
                return jsonify({'success': True, 'message': f'Campaign "{campaign_name}" deleted successfully'})
                
            except Exception as e:
                db.session.rollback()
                logger.error(f"Campaign deletion error: {str(e)}")
                return jsonify({'success': False, 'message': f'Failed to delete campaign: {str(e)}'}), 500

    except Exception as e:
        logger.error(f"Campaign detail error: {str(e)}")
        return jsonify({'success': False, 'message': 'Operation failed'}), 500

@app.route('/api/campaigns/<int:campaign_id>/start', methods=['POST'])
@login_required
def start_campaign(campaign_id):
    try:
        campaign = db.session.get(Campaign, campaign_id)
        if not campaign:
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404

        # Check ownership
        if not current_user.is_admin() and campaign.user_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403

        campaign.status = 'active'
        campaign.updated_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Campaign {campaign_id} started by user {current_user.username}")
        return jsonify({'success': True, 'message': 'Campaign started successfully'})

    except Exception as e:
        logger.error(f"Error starting campaign: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/campaigns/<int:campaign_id>/pause', methods=['POST'])
@login_required
def pause_campaign(campaign_id):
    try:
        campaign = db.session.get(Campaign, campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404

        # Check ownership
        if not current_user.is_admin() and campaign.user_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403

        campaign.status = 'paused'
        campaign.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Campaign paused'})

    except Exception as e:
        logger.error(f"Campaign pause error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to pause campaign'}), 500

@app.route('/api/campaigns/<int:campaign_id>/stats')
@login_required
def get_campaign_stats(campaign_id):
    try:
        campaign = db.session.get(Campaign, campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404
        
        # Check ownership
        if not current_user.is_admin() and campaign.user_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        
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
        
        # Get total recipients assigned to this campaign
        total_recipients = CampaignRecipient.query.filter_by(campaign_id=campaign_id).count()
        
        return jsonify({
            'campaign_id': campaign_id,
            'total_emails': total_emails,
            'sent_emails': sent_emails,
            'failed_emails': failed_emails,
            'success_rate': round(success_rate, 1),
            'today_emails': today_emails,
            'progress': calculate_campaign_progress(campaign),
            'daily_target': campaign.daily_volume,
            'total_recipients': total_recipients
        })
        
    except Exception as e:
        logger.error(f"Error fetching campaign stats: {str(e)}")
        return jsonify({'error': 'Failed to fetch stats'}), 500

@app.route('/api/campaigns/<int:campaign_id>/debug')
@login_required
def debug_campaign_deletion(campaign_id):
    """Debug what's preventing campaign deletion"""
    try:
        campaign = db.session.get(Campaign, campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404
            
        # Check ownership
        if not current_user.is_admin() and campaign.user_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
            
        email_log_count = EmailLog.query.filter_by(campaign_id=campaign_id).count()
        recipient_count = CampaignRecipient.query.filter_by(campaign_id=campaign_id).count()
        
        return jsonify({
            'campaign_id': campaign_id,
            'campaign_name': campaign.name,
            'user_id': campaign.user_id,
            'current_user_id': current_user.id,
            'is_demo': current_user.is_demo(),
            'is_admin': current_user.is_admin(),
            'email_logs': email_log_count,
            'campaign_recipients': recipient_count,
            'can_delete': not current_user.is_demo(),
            'status': campaign.status
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/validate-smtp', methods=['POST'])
@login_required
def validate_smtp():
    """Enhanced SMTP validation with real connection testing"""
    try:
        data = request.get_json()
        provider = data.get('provider')
        username = data.get('username', '')
        password = data.get('password', '')
        
        if not all([provider, username, password]):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        if provider not in SMTP_PROVIDERS:
            return jsonify({'success': False, 'message': 'Invalid provider'}), 400
        
        # Provider-specific validation
        if 'amazon_ses' in provider and not username.startswith('AKIA'):
            return jsonify({'success': False, 'message': 'Amazon SES username should start with AKIA'}), 400

        # Real SMTP connection test (skip for demo users)
        if current_user.is_demo():
            return jsonify({
                'success': True, 
                'message': 'Demo validation successful',
                'provider_info': SMTP_PROVIDERS[provider]
            })

        # Test actual SMTP connection for non-demo users
        smtp_config = SMTP_PROVIDERS[provider]
        
        try:
            logger.info(f"Testing SMTP connection to {smtp_config['host']}:{smtp_config['port']}")
            
            server = smtplib.SMTP(smtp_config['host'], smtp_config['port'])
            server.starttls()
            server.login(username, password)
            server.quit()
            
            logger.info(f"SMTP validation successful for {provider}")
            return jsonify({
                'success': True,
                'message': 'SMTP configuration validated successfully',
                'provider_info': smtp_config
            })
            
        except smtplib.SMTPAuthenticationError:
            logger.error(f"SMTP Authentication failed for {provider}")
            return jsonify({
                'success': False,
                'message': 'Authentication failed. Please check your username and password.',
                'help_text': smtp_config.get('help_text', '')
            }), 400
            
        except smtplib.SMTPServerDisconnected:
            logger.error(f"SMTP Server disconnected for {provider}")
            return jsonify({
                'success': False,
                'message': 'Connection to SMTP server failed. Please try again.',
                'help_text': smtp_config.get('help_text', '')
            }), 400
            
        except Exception as e:
            logger.error(f"SMTP validation error: {str(e)}")
            return jsonify({
                'success': False,
                'message': f'SMTP configuration test failed: {str(e)}',
                'help_text': smtp_config.get('help_text', '')
            }), 400
            
    except Exception as e:
        logger.error(f"SMTP validation error: {str(e)}")
        return jsonify({'success': False, 'message': 'Validation failed'}), 500

@app.route('/api/email-logs/<int:campaign_id>')
@login_required
def get_email_logs(campaign_id):
    """Get email logs for a specific campaign"""
    try:
        campaign = db.session.get(Campaign, campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404
        
        # Check ownership
        if not current_user.is_admin() and campaign.user_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403

        # Pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        
        logs = EmailLog.query.filter_by(campaign_id=campaign_id)\
                           .order_by(EmailLog.sent_at.desc())\
                           .paginate(page=page, per_page=per_page, error_out=False)
        
        log_data = []
        for log in logs.items:
            log_data.append({
                'id': log.id,
                'recipient': log.recipient,
                'subject': log.subject,
                'status': log.status,
                'error_message': log.error_message,
                'sent_at': log.sent_at.isoformat() if log.sent_at else None
            })
        
        return jsonify({
            'logs': log_data,
            'pagination': {
                'page': logs.page,
                'pages': logs.pages,
                'per_page': logs.per_page,
                'total': logs.total,
                'has_next': logs.has_next,
                'has_prev': logs.has_prev
            }
        })
        
    except Exception as e:
        logger.error(f"Error fetching email logs: {str(e)}")
        return jsonify({'error': 'Failed to fetch email logs'}), 500

@app.route('/api/providers')
@login_required
def get_providers():
    """Get available SMTP providers"""
    return jsonify(SMTP_PROVIDERS)

@app.route('/api/test-email', methods=['POST'])
@login_required
def send_test_email():
    """Send a test email to verify SMTP configuration"""
    try:
        if current_user.is_demo():
            return jsonify({
                'success': False, 
                'message': 'Demo accounts cannot send test emails'
            }), 403
        
        data = request.get_json()
        campaign_id = data.get('campaign_id')
        test_email = data.get('test_email', current_user.email)
        
        if not campaign_id:
            return jsonify({'success': False, 'message': 'Campaign ID required'}), 400
        
        campaign = db.session.get(Campaign, campaign_id)
        if not campaign:
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404
        
        # Check ownership
        if campaign.user_id != current_user.id and not current_user.is_admin():
            return jsonify({'error': 'Access denied'}), 403
        
        # Send test email
        subject = f"Test Email from {campaign.name}"
        body = f"""
        Hello,
        
        This is a test email from your KEXY Email Warmup campaign: {campaign.name}
        
        If you receive this email, your SMTP configuration is working correctly.
        
        Campaign Details:
        - Provider: {SMTP_PROVIDERS[campaign.provider]['name']}
        - Email: {campaign.email}
        - Industry: {campaign.industry}
        
        Best regards,
        KEXY Email Warmup Team
        """
        
        success = send_smtp_email(campaign, test_email, subject, body)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'Test email sent successfully to {test_email}'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to send test email. Please check your SMTP configuration.'
            }), 400
            
    except Exception as e:
        logger.error(f"Test email error: {str(e)}")
        return jsonify({'success': False, 'message': 'Test email failed'}), 500

@app.route('/api/admin/users')
@admin_required
def admin_get_users():
    """Admin endpoint to get all users"""
    try:
        users = User.query.all()
        return jsonify([user.to_dict() for user in users])
    except Exception as e:
        logger.error(f"Admin users error: {str(e)}")
        return jsonify({'error': 'Failed to fetch users'}), 500

@app.route('/api/admin/users/<int:user_id>/toggle-status', methods=['POST'])
@admin_required
def admin_toggle_user_status(user_id):
    """Admin endpoint to toggle user active status"""
    try:
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.is_active = not user.is_active
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'User {user.username} {"activated" if user.is_active else "deactivated"}',
            'user': user.to_dict()
        })
        
    except Exception as e:
        logger.error(f"Admin toggle user error: {str(e)}")
        return jsonify({'error': 'Failed to toggle user status'}), 500

@app.route('/api/admin/system-stats')
@admin_required
def admin_system_stats():
    """Admin endpoint for system statistics"""
    try:
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        demo_users = User.query.filter_by(role='demo').count()
        
        total_campaigns = Campaign.query.count()
        active_campaigns = Campaign.query.filter_by(status='active').count()
        
        total_emails = EmailLog.query.count()
        successful_emails = EmailLog.query.filter_by(status='sent').count()
        
        total_recipients = WarmupRecipient.query.count()
        active_recipients = WarmupRecipient.query.filter_by(is_active=True).count()
        
        user_recipients = Recipient.query.count()
        
        # Recent activity
        recent_logins = LoginAttempt.query.filter_by(success=True)\
                                         .order_by(LoginAttempt.timestamp.desc())\
                                         .limit(10).all()
        
        recent_campaigns = Campaign.query.order_by(Campaign.created_at.desc())\
                                        .limit(5).all()
        
        return jsonify({
            'users': {
                'total': total_users,
                'active': active_users,
                'demo': demo_users
            },
            'campaigns': {
                'total': total_campaigns,
                'active': active_campaigns
            },
            'recipients': {
                'warmup_total': total_recipients,
                'warmup_active': active_recipients,
                'user_total': user_recipients
            },
            'emails': {
                'total': total_emails,
                'successful': successful_emails,
                'success_rate': round((successful_emails / total_emails * 100) if total_emails > 0 else 0, 1)
            },
            'recent_activity': {
                'logins': [{'email': l.email, 'timestamp': l.timestamp.isoformat()} for l in recent_logins],
                'campaigns': [{'name': c.name, 'user_id': c.user_id, 'created_at': c.created_at.isoformat()} for c in recent_campaigns]
            }
        })
        
    except Exception as e:
        logger.error(f"Admin system stats error: {str(e)}")
        return jsonify({'error': 'Failed to fetch system stats'}), 500

# Enhanced Error Handlers with template fallbacks
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors with proper template fallback"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    
    try:
        return render_template('404.html'), 404
    except Exception as template_error:
        logger.error(f"404 template error: {str(template_error)}")
        # Fallback HTML response if template is missing
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Page Not Found</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
                h1 { color: #dc3545; }
                a { color: #007bff; text-decoration: none; }
                a:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <h1>404 - Page Not Found</h1>
            <p>The page you're looking for doesn't exist.</p>
            <a href="/">Go Home</a>
        </body>
        </html>
        ''', 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors with proper template fallback"""
    db.session.rollback()
    
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    
    try:
        return render_template('500.html'), 500
    except Exception as template_error:
        logger.error(f"500 template error: {str(template_error)}")
        # Fallback HTML response if template is missing
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Server Error</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
                h1 { color: #dc3545; }
                a { color: #007bff; text-decoration: none; }
                a:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <h1>500 - Server Error</h1>
            <p>Something went wrong on our end. Please try again later.</p>
            <a href="/">Go Home</a>
        </body>
        </html>
        ''', 500

@app.errorhandler(403)
def forbidden(error):
    """Handle 403 errors with proper template fallback"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Access forbidden'}), 403
    
    try:
        return render_template('403.html'), 403
    except Exception as template_error:
        logger.error(f"403 template error: {str(template_error)}")
        # Fallback HTML response if template is missing
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Access Forbidden</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
                h1 { color: #dc3545; }
                a { color: #007bff; text-decoration: none; }
                a:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <h1>403 - Access Forbidden</h1>
            <p>You don't have permission to access this resource.</p>
            <a href="/">Go Home</a>
        </body>
        </html>
        ''', 403

@app.errorhandler(Exception)
def handle_unexpected_error(error):
    """Handle any unexpected errors"""
    db.session.rollback()
    logger.error(f"Unexpected error: {str(error)}", exc_info=True)
    
    if request.path.startswith('/api/'):
        return jsonify({'error': 'An unexpected error occurred'}), 500
    
    try:
        return render_template('500.html'), 500
    except Exception as template_error:
        logger.error(f"Template error in unexpected handler: {str(template_error)}")
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Error</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
                h1 { color: #dc3545; }
                a { color: #007bff; text-decoration: none; }
                a:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <h1>An Error Occurred</h1>
            <p>Something unexpected happened. Please try again later.</p>
            <a href="/">Go Home</a>
        </body>
        </html>
        ''', 500

# Database Initialization
def create_tables():
    """Create database tables with error handling"""
    try:
        with app.app_context():
            db.create_all()
            logger.info("✅ Database tables created successfully")
            
            # Create demo user if it doesn't exist
            create_demo_user()
            
            # Create initial recipients if none exist
            create_initial_recipients()
            
            logger.info("🔧 Database initialization completed")
            
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {str(e)}")
        raise

# Application Startup
if __name__ == '__main__':
    try:
        print("🚀 Initializing KEXY Email Warmup application...")
        
        # Call initialization on startup (AUTO-MIGRATION)
        init_database()
        
        # Start background scheduler
        start_warmup_scheduler()
        
        # Start ProtonMail multi-account monitoring
        protonmail_multi_reply.start_monitoring()
        
        # Get port from environment
        port = int(os.environ.get('PORT', 5000))
        
        print(f"🌟 KEXY Email Warmup starting on port {port}")
        print("🔧 Features enabled:")
        print(f"   • Scheduling: {'✅' if SCHEDULE_AVAILABLE or APSCHEDULER_AVAILABLE else '❌'}")
        print(f"   • Email sending: ✅")
        print(f"   • User authentication: ✅")
        print(f"   • Admin panel: ✅")
        print(f"   • Database-driven recipients: ✅")
        print(f"   • User-specific recipients: ✅")
        print(f"   • Auto-migration: ✅")
        
        # Check recipient count
        try:
            with app.app_context():
                warmup_recipient_count = WarmupRecipient.query.count()
                user_recipient_count = Recipient.query.count()
                print(f"   • Warmup recipients available: {warmup_recipient_count}")
                print(f"   • User recipients available: {user_recipient_count}")
        except:
            print(f"   • Recipients: Not yet initialized")
        
        # Run the application
        app.run(
            host='0.0.0.0',
            port=port,
            debug=os.environ.get('FLASK_ENV') == 'development'
        )
        
    except Exception as e:
        logger.error(f"❌ Application startup failed: {str(e)}")
        print(f"💥 Startup Error: {str(e)}")
        raise
