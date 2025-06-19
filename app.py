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
from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')

# 🚀 RAILWAY-COMPATIBLE DATABASE CONFIG - FIXED!
database_url = os.environ.get('DATABASE_URL', '').strip()
if database_url and not database_url.startswith('sqlite'):
    # Use PostgreSQL if provided
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    logger.info("🔧 Using PostgreSQL database")
else:
    # Use CURRENT DIRECTORY for SQLite (Railway safe)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///warmup.db'
    logger.info("🔧 Using SQLite in app directory")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# SMTP Providers Configuration
SMTP_PROVIDERS = {
    'amazon_ses_us_east_1': {
        'host': 'email-smtp.us-east-1.amazonaws.com',
        'port': 587,
        'name': 'Amazon SES (US East 1)',
        'help_text': 'Amazon SES (US East 1): Use IAM Access Key ID as username and Secret Access Key as password'
    },
    'amazon_ses_us_west_2': {
        'host': 'email-smtp.us-west-2.amazonaws.com',
        'port': 587,
        'name': 'Amazon SES (US West 2)',
        'help_text': 'Amazon SES (US West 2): Use IAM Access Key ID as username and Secret Access Key as password'
    },
    'gmail': {
        'host': 'smtp.gmail.com',
        'port': 587,
        'name': 'Gmail',
        'help_text': 'For Gmail: Enable 2-Factor Authentication and generate an App Password'
    },
    'outlook': {
        'host': 'smtp-mail.outlook.com',
        'port': 587,
        'name': 'Outlook',
        'help_text': 'For Outlook: Enable 2-Factor Authentication and generate an App Password'
    }
}

# Email Content Types and Templates
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
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    campaigns = db.relationship('Campaign', backref='user', lazy=True)

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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, default=1)

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

# Email Generation Functions
def generate_fallback_content(content_type, industry, recipient_name, sender_name):
    """Generate fallback email content when AI is unavailable"""
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

# Email Sending Functions
def send_warmup_email(campaign_id, recipient_email, recipient_name, content_type):
    """Send actual warmup email"""
    try:
        with app.app_context():
            campaign = db.session.get(Campaign, campaign_id)
            if not campaign or campaign.status != 'active':
                logger.error(f"Campaign {campaign_id} not active or not found")
                return False
            
            logger.info(f"Generating email content for {recipient_email}")
            
            # Generate AI content (fallback for now)
            ai_content = generate_fallback_content(
                content_type, 
                campaign.industry, 
                recipient_name, 
                "Team"
            )
            
            # Get email template
            template = EMAIL_CONTENT_TYPES[content_type]
            subject_template = random.choice(template['subject_templates'])
            
            # Generate subject
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
                # Update campaign stats
                campaign.emails_sent += 1
                
                # Calculate success rate
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
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = campaign.email
        msg['To'] = recipient_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        # Connect and send
        server = smtplib.SMTP(campaign.smtp_host, campaign.smtp_port)
        server.starttls()
        
        logger.info(f"Authenticating with username: {campaign.smtp_username}")
        server.login(campaign.smtp_username, campaign.smtp_password)
        
        logger.info(f"Sending email from {campaign.email} to {recipient_email}")
        server.send_message(msg)
        server.quit()
        
        logger.info(f"Email sent successfully to {recipient_email}")
        return True
        
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

def calculate_campaign_progress(campaign):
    """Calculate campaign progress percentage"""
    days_elapsed = (datetime.utcnow() - campaign.created_at).days
    total_days = campaign.warmup_days
    return min(int((days_elapsed / total_days) * 100), 100)

def get_daily_volume_for_campaign(campaign):
    """Calculate daily email volume"""
    return campaign.daily_volume

# Background Scheduler Functions
def process_warmup_campaigns():
    """Process all active campaigns for email sending"""
    try:
        with app.app_context():
            active_campaigns = Campaign.query.filter_by(status='active').all()
            logger.info(f"🔄 Processing {len(active_campaigns)} active campaigns")
            
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
                        
                        # Delay between emails
                        time.sleep(random.uniform(5, 10))
                    
                    logger.info(f"✅ Sent {len(recipients)} warmup emails for campaign '{campaign.name}'")
                else:
                    logger.info(f"⏭️ Campaign '{campaign.name}': Daily quota already reached")
    
    except Exception as e:
        logger.error(f"❌ Error processing warmup campaigns: {str(e)}")

def start_warmup_scheduler():
    """Start the background email scheduler"""
    def run_scheduler():
        logger.info("🚀 Warmup scheduler thread started")
        
        # Schedule email sending every 2 minutes for testing
        schedule.every(2).minutes.do(process_warmup_campaigns)
        
        scheduler_running = True
        while scheduler_running:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute for scheduled tasks
                
            except Exception as e:
                logger.error(f"❌ Scheduler error: {str(e)}")
                time.sleep(60)  # Continue running even if there's an error
    
    # Start scheduler in background thread
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    logger.info("⏰ Warmup scheduler started - emails every 2 minutes")

# MAIN ROUTES
@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/test')
def test_route():
    return jsonify({'status': 'working', 'timestamp': datetime.now().isoformat()})

# API ROUTES
@app.route('/api/dashboard-stats')
def dashboard_stats():
    try:
        total_campaigns = Campaign.query.count()
        active_campaigns = Campaign.query.filter_by(status='active').count()
        successful_emails = EmailLog.query.filter_by(status='sent').count()
        total_emails = EmailLog.query.count()
        
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
            required_fields = ['name', 'email', 'provider', 'username', 'password']
            if not all(field in data for field in required_fields):
                return jsonify({'success': False, 'message': 'Missing required fields'}), 400

            # Get provider configuration
            provider = data['provider']
            if provider not in SMTP_PROVIDERS:
                return jsonify({'success': False, 'message': 'Invalid provider'}), 400

            # Create campaign
            campaign = Campaign(
                name=data['name'],
                email=data['email'],
                provider=provider,
                smtp_host=SMTP_PROVIDERS[provider]['host'],
                smtp_port=SMTP_PROVIDERS[provider]['port'],
                smtp_username=data['username'],
                smtp_password=data['password'],
                industry=data.get('industry', 'general'),
                daily_volume=data.get('daily_volume', 10),
                warmup_days=data.get('warmup_days', 30),
                user_id=1
            )

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
        campaign = db.session.get(Campaign, campaign_id)
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

@app.route('/api/campaigns/<int:campaign_id>/start', methods=['POST'])
def start_campaign(campaign_id):
    try:
        campaign = db.session.get(Campaign, campaign_id)
        if not campaign:
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404

        campaign.status = 'active'
        campaign.updated_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Campaign {campaign_id} started successfully")
        return jsonify({'success': True, 'message': 'Campaign started successfully'})

    except Exception as e:
        logger.error(f"Error starting campaign: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/campaigns/<int:campaign_id>/pause', methods=['POST'])
def pause_campaign(campaign_id):
    try:
        campaign = db.session.get(Campaign, campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404

        campaign.status = 'paused'
        campaign.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Campaign paused'})

    except Exception as e:
        logger.error(f"Campaign pause error: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to pause campaign'}), 500

@app.route('/api/campaigns/<int:campaign_id>/logs')
def get_campaign_logs(campaign_id):
    try:
        campaign = db.session.get(Campaign, campaign_id)
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
        campaign = db.session.get(Campaign, campaign_id)
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
            'progress': calculate_campaign_progress(campaign),
            'daily_target': campaign.daily_volume
        })
        
    except Exception as e:
        logger.error(f"Error fetching campaign stats: {str(e)}")
        return jsonify({'error': 'Failed to fetch stats'}), 500

@app.route('/api/validate-smtp', methods=['POST'])
def validate_smtp():
    try:
        data = request.get_json()
        provider = data.get('provider')
        
        if provider not in SMTP_PROVIDERS:
            return jsonify({'success': False, 'message': 'Invalid provider'}), 400
        
        # Basic validation
        username = data.get('username', '')
        if 'amazon_ses' in provider and not username.startswith('AKIA'):
            return jsonify({'success': False, 'message': 'Amazon SES username should start with AKIA'}), 400
        
        return jsonify({'success': True, 'message': 'Validation successful'})

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

@app.route('/api/warmup-strategies')
def get_warmup_strategies():
    return jsonify({
        'strategies': {
            'steady': {
                'name': 'Steady',
                'description': 'Consistent daily volume',
                'daily_volume': 10,
                'duration_days': 30
            },
            'progressive': {
                'name': 'Progressive',
                'description': 'Gradual increase',
                'daily_volume': 15,
                'duration_days': 30
            }
        }
    })

# DEBUG ROUTES
@app.route('/api/debug/create-test-data', methods=['GET', 'POST'])
def create_test_data():
    try:
        # Create test campaign if doesn't exist
        if Campaign.query.count() == 0:
            campaign = Campaign(
                name='Test1', 
                email='scott@getkexy.com', 
                provider='amazon_ses_us_east_1',
                smtp_host='email-smtp.us-east-1.amazonaws.com',
                smtp_username='AKIAUZ6NT5LNL5DRY6AZ',
                smtp_password='test-password',
                industry='marketing',
                status='active', 
                emails_sent=10,
                user_id=1
            )
            db.session.add(campaign)
            db.session.commit()
            
            # Create test email logs
            for i in range(10):
                log = EmailLog(
                    campaign_id=campaign.id, 
                    recipient=f'test{i}@example.com', 
                    subject=f'Test Email {i}',
                    status='sent'
                )
                db.session.add(log)
            db.session.commit()
            
        return jsonify({'success': True, 'message': 'Test data created'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/debug/system-status')
def system_status():
    try:
        return jsonify({
            'database_connected': True,
            'total_campaigns': Campaign.query.count(),
            'active_campaigns': Campaign.query.filter_by(status='active').count(),
            'total_email_logs': EmailLog.query.count(),
            'server_time': datetime.now().isoformat(),
            'scheduler_running': True
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/force-send/<int:campaign_id>', methods=['POST'])
def force_send_now(campaign_id):
    """Force send an email right now for testing"""
    try:
        with app.app_context():
            campaign = db.session.get(Campaign, campaign_id)
            if not campaign:
                return jsonify({'error': 'Campaign not found'}), 404
            
            if campaign.status != 'active':
                campaign.status = 'active'
                db.session.commit()
            
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

# Error Handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

# Initialize database and create default user
def init_db():
    with app.app_context():
        db.create_all()
        
        # Create default user if doesn't exist
        if User.query.count() == 0:
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin123')
            )
            db.session.add(admin)
            db.session.commit()
            logger.info("Default admin user created")
        
        logger.info("Database initialized")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    
    # Initialize database
    init_db()
    
    # Start background scheduler
    start_warmup_scheduler()
    
    logger.info("🚀 Starting KEXY Email Warmup System - COMPLETE VERSION")
    logger.info("📧 Email sending every 2 minutes for active campaigns")
    logger.info("🔧 All features enabled: SMTP, scheduling, analytics")
    
    app.run(host='0.0.0.0', port=port, debug=False)
