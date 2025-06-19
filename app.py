#!/usr/bin/env python3

import os
import logging
from datetime import datetime, timedelta
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
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///warmup.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# COMPLETE Database Models
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
    smtp_password = db.Column(db.String(500))  # Simplified - no encryption for now
    industry = db.Column(db.String(100))
    daily_volume = db.Column(db.Integer, default=10)
    warmup_days = db.Column(db.Integer, default=30)
    status = db.Column(db.String(20), default='created')
    emails_sent = db.Column(db.Integer, default=0)
    success_rate = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
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
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class EmailLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    recipient = db.Column(db.String(255))
    subject = db.Column(db.String(500))
    status = db.Column(db.String(20))
    error_message = db.Column(db.Text)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    }
}

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

# API ROUTES - COMPLETE SET
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
                smtp_password=data['password'],  # Store directly for now
                industry=data.get('industry', 'general'),
                daily_volume=data.get('daily_volume', 10),
                warmup_days=data.get('warmup_days', 30),
                user_id=1  # Default user
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
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404

        campaign.status = 'active'
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Campaign started successfully'})

    except Exception as e:
        logger.error(f"Error starting campaign: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

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
        logger.error(f"Campaign pause error: {str(e)}")
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
            'progress': min(100, int((datetime.utcnow() - campaign.created_at).days / campaign.warmup_days * 100)),
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
        
        # For now, just validate format - actual SMTP testing can be added later
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
@app.route('/api/debug/create-test-data', methods=['POST'])
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
            'server_time': datetime.now().isoformat()
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
    
    logger.info("🚀 Starting KEXY Email Warmup System")
    app.run(host='0.0.0.0', port=port, debug=False)
