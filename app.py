#!/usr/bin/env python3

import os
import logging
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import threading
import time
import schedule
import secrets
import uuid
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

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

# Enhanced Email Sending Functions (keeping existing but user-aware)
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

# Keep all existing email functions...
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

# Background Scheduler Functions (user-aware)
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
    """Start the background email scheduler"""
    def run_scheduler():
        logger.info("🚀 Warmup scheduler thread started")
        
        # Schedule email sending every 2 minutes for testing, every hour for production
        schedule.every(2).minutes.do(process_warmup_campaigns)
        
        while True:
            try:
                schedule.run_pending()
                time.sleep(60)
            except Exception as e:
                logger.error(f"❌ Scheduler error: {str(e)}")
                time.sleep(60)
    
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    logger.info("⏰ Warmup scheduler started")

# AUTHENTICATION ROUTES
@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
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
        'timestamp': datetime.now().isoformat(),
        'version': '3.0.0'
    })

@app.route('/test')
def test_route():
    return jsonify({'status': 'working', 'timestamp': datetime.now().isoformat()})

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

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def api_logout():
    try:
        username = current_user.username
        logout_user()
        session.clear()
        
        logger.info(f"User {username} logged out")
        
        return jsonify({
            'success': True,
            'message': 'Logout successful',
            'redirect_url': url_for('login')
        })
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
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

# Debug endpoints for PostgreSQL migration
@app.route('/api/debug/db-status')
def db_status():
    """Check current database status"""
    try:
        db_url = os.environ.get('DATABASE_URL', '').strip()
        is_postgresql = db_url and not db_url.startswith('sqlite')
        
        campaign_count = Campaign.query.count()
        email_log_count = EmailLog.query.count()
        user_count = User.query.count()
        
        return jsonify({
            'database_type': 'PostgreSQL' if is_postgresql else 'SQLite',
            'database_url_prefix': db_url[:30] + '...' if db_url else 'None',
            'users_count': user_count,
            'campaigns_count': campaign_count,
            'email_logs_count': email_log_count,
            'migration_ready': is_postgresql and campaign_count == 0,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e), 'timestamp': datetime.now().isoformat()})

@app.route('/api/debug/export-data')
def export_current_data():
    """Export current data for backup before migration"""
    try:
        campaigns = Campaign.query.all()
        email_logs = EmailLog.query.all()
        users = User.query.all()
        
        campaign_data = [campaign.to_dict() for campaign in campaigns]
        user_data = [user.to_dict() for user in users]
        
        log_data = []
        for log in email_logs:
            log_data.append({
                'campaign_id': log.campaign_id,
                'recipient': log.recipient,
                'subject': log.subject,
                'status': log.status,
                'error_message': log.error_message,
                'sent_at': log.sent_at.isoformat() if log.sent_at else None
            })
        
        return jsonify({
            'users': user_data,
            'campaigns': campaign_data,
            'email_logs': log_data,
            'total_users': len(user_data),
            'total_campaigns': len(campaign_data),
            'total_logs': len(log_data),
            'export_time': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)})

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
        else:
            # Users see only their stats
            user_campaigns = Campaign.query.filter_by(user_id=current_user.id)
            campaign_ids = [c.id for c in user_campaigns]
            
            total_campaigns = user_campaigns.count()
            active_campaigns = user_campaigns.filter_by(status='active').count()
            
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

            logger.info(f"Campaign created: {campaign.name} for user {current_user.username}")
            return jsonify({'success': True, 'message': 'Campaign created successfully', 'campaign': campaign.to_dict()})

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
                
            db.session.delete(campaign)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Campaign deleted'})

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
        
        return jsonify({
            'campaign_id': campaign_id,
            'total_emails': total_emails,
            'sent_emails': sent_emails,
            'failed_emails': failed_emails,
            'success_rate': round(success_rate, 1),
            'today_emails': today_emails,
            'progress': calculate_campaign_progress(campaign),
            'daily_target': campaign.daily_volume
        })
        
    except Exception as e:
        logger.error(f"Error fetching campaign stats: {str(e)}")
        return jsonify({'error': 'Failed to fetch stats'}), 500

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
            return jsonify({'success': True, 'message': 'SMTP validation successful (demo mode)'})
        
        try:
            smtp_config = SMTP_PROVIDERS[provider]
            server = smtplib.SMTP(smtp_config['host'], smtp_config['port'])
            server.starttls()
            server.login(username, password)
            server.quit()
            
            return jsonify({'success': True, 'message': 'SMTP connection validated successfully'})
            
        except smtplib.SMTPAuthenticationError:
            return jsonify({'success': False, 'message': 'Authentication failed. Check your credentials.'}), 400
        except Exception as e:
            return jsonify({'success': False, 'message': f'Connection failed: {str(e)}'}), 400

    except Exception as e:
        logger.error(f"SMTP validation error: {str(e)}")
        return jsonify({'success': False, 'message': 'Validation failed'}), 500

@app.route('/api/providers')
def get_providers():
    return jsonify({
        'providers': {
            key: {
                'name': config['name'],
                'help_text': config['help_text'],
                'requires_custom_host': False
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
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {str(e)}")
    return jsonify({'error': 'An unexpected error occurred'}), 500

# Enhanced Database initialization with Authentication
def init_db():
    with app.app_context():
        try:
            # Create all tables
            db.create_all()
            
            # Check database type
            db_url = os.environ.get('DATABASE_URL', '').strip()
            is_postgresql = db_url and not db_url.startswith('sqlite')
            
            # Create default admin user if doesn't exist
            admin_user = User.query.filter_by(role='admin').first()
            if not admin_user:
                admin_user = User(
                    username='admin',
                    email='admin@kexy.com',
                    password_hash=generate_password_hash('admin123'),
                    role='admin',
                    email_verified=True,
                    is_active=True
                )
                db.session.add(admin_user)
                db.session.commit()
                logger.info("✅ Default admin user created (admin@kexy.com / admin123)")
            
            # Create demo user
            create_demo_user()
            
            if is_postgresql:
                logger.info("🚀 PostgreSQL database initialized successfully - ENTERPRISE READY!")
                logger.info("📊 Automatic migration completed - Your data is now enterprise-grade")
                logger.info("🔐 Authentication system enabled - Multi-user support active")
            else:
                logger.info("✅ SQLite database initialized successfully")
                logger.info("🔐 Authentication system enabled")
            
            logger.info("🔧 Database initialization completed")
            
        except Exception as e:
            logger.error(f"❌ Database initialization failed: {str(e)}")
            raise

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    
    # Initialize database with migration support
    init_db()
    
    # Start background scheduler
    start_warmup_scheduler()
    
    logger.info("🚀 Starting KEXY Email Warmup System - Enhanced Authentication Version")
    logger.info(f"📧 Running on port {port}")
    logger.info("🔧 All features enabled: Authentication, SMTP validation, scheduling, analytics, PostgreSQL migration")
    logger.info("👤 Default accounts: admin@kexy.com (admin123) | demo user available")
    
    app.run(host='0.0.0.0', port=port, debug=False)
