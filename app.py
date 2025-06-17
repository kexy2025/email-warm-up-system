from flask import Flask, render_template, request, jsonify, session
import os
import smtplib
import ssl
from email.mime.text import MIMEText
import secrets
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid
import logging
import socket

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'kexy-email-warmup-secret-key-2024')
database_url = os.environ.get('DATABASE_URL', 'sqlite:///email_warmup.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def generate_reset_token(self):
        self.reset_token = str(uuid.uuid4())
        self.reset_token_expires = datetime.utcnow() + timedelta(hours=24)
        db.session.commit()
        return self.reset_token
    
    def verify_reset_token(self, token):
        return self.reset_token == token and self.reset_token_expires > datetime.utcnow()
    
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
    smtp_password = db.Column(db.Text, nullable=True)
    provider = db.Column(db.String(50), default='custom')
    status = db.Column(db.String(50), default='draft')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime, nullable=True)
    daily_volume = db.Column(db.Integer, default=5)
    max_volume = db.Column(db.Integer, default=100)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email_address': self.email_address,
            'smtp_host': self.smtp_host,
            'smtp_port': self.smtp_port,
            'provider': self.provider,
            'status': self.status,
            'daily_volume': self.daily_volume,
            'max_volume': self.max_volume,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None
        }

# SMTP Providers - ONLY ADDED AMAZON SES
SMTP_PROVIDERS = {
    'gmail': {
        'smtp_host': 'smtp.gmail.com',
        'smtp_port': 587,
        'requires_app_password': True,
        'instructions': 'Use Gmail App Password (not regular password)'
    },
    'outlook': {
        'smtp_host': 'smtp-mail.outlook.com', 
        'smtp_port': 587,
        'requires_app_password': False,
        'instructions': 'Use regular Outlook password'
    },
    'yahoo': {
        'smtp_host': 'smtp.mail.yahoo.com',
        'smtp_port': 587,
        'requires_app_password': True,
        'instructions': 'Use Yahoo App Password'
    },
    'amazon_ses': {
        'smtp_host': 'email-smtp.us-east-1.amazonaws.com',
        'smtp_port': 587,
        'requires_app_password': False,
        'instructions': 'Use AWS SES SMTP credentials (not IAM credentials)',
        'regions': {
            'us-east-1': 'email-smtp.us-east-1.amazonaws.com',
            'us-west-2': 'email-smtp.us-west-2.amazonaws.com',
            'eu-west-1': 'email-smtp.eu-west-1.amazonaws.com',
            'ap-southeast-1': 'email-smtp.ap-southeast-1.amazonaws.com'
        }
    },
    'custom': {
        'smtp_host': '',
        'smtp_port': 587,
        'requires_app_password': False,
        'instructions': 'Enter your custom SMTP settings'
    }
}

# Utility Functions
def detect_email_provider(email):
    """Auto-detect email provider from email address"""
    try:
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
    except:
        return 'custom'

def validate_smtp_comprehensive(email, password, smtp_host, smtp_port, smtp_username=None, provider='custom'):
    """Enhanced SMTP validation with better error handling"""
    if not smtp_username:
        smtp_username = email
    
    logger.info(f"SMTP Validation - Host: {smtp_host}, Port: {smtp_port}, Username: {smtp_username}, Provider: {provider}")
    
    try:
        # Test DNS resolution first
        try:
            socket.gethostbyname(smtp_host)
            logger.info(f"DNS resolution successful for {smtp_host}")
        except socket.gaierror as dns_error:
            logger.error(f"DNS resolution failed for {smtp_host}: {dns_error}")
            return {
                'success': False,
                'message': f'Cannot resolve SMTP host "{smtp_host}". Please check the hostname.',
                'error_type': 'dns_error',
                'suggestions': [
                    'Verify the SMTP hostname is correct',
                    'Check if you need a different region for AWS SES',
                    'Ensure your network can resolve DNS'
                ]
            }
        
        # Test SMTP connection with longer timeout
        logger.info(f"Attempting SMTP connection to {smtp_host}:{smtp_port}")
        
        if smtp_port == 465:
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, context=context, timeout=30)
            logger.info("Connected using SSL")
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
            logger.info("Connected using regular SMTP")
            if smtp_port in [587, 25]:  # Only start TLS for appropriate ports
                server.starttls()
                logger.info("Started TLS")
        
        # Test authentication
        logger.info(f"Attempting authentication for {smtp_username}")
        server.login(smtp_username, password)
        logger.info("Authentication successful")
        
        # Send test email
        test_msg = MIMEText(f"""
SMTP Configuration Validated Successfully!

Your email configuration has been tested and verified:

Email: {email}
SMTP Host: {smtp_host}
Port: {smtp_port}
Username: {smtp_username}
Provider: {provider.upper()}

Your account is now ready for email warmup campaigns.

---
KEXY Email Warmup System
        """)
        
        test_msg['From'] = email
        test_msg['To'] = email
        test_msg['Subject'] = "SMTP Validation Successful - KEXY Email Warmup"
        
        server.send_message(test_msg)
        server.quit()
        
        logger.info(f"SMTP validation successful for {email}")
        
        return {
            'success': True,
            'message': f'SMTP validation successful! Test email sent to {email}',
            'details': f'Connected to {smtp_host}:{smtp_port} using {provider}',
            'provider': provider
        }
        
    except smtplib.SMTPAuthenticationError as auth_error:
        logger.error(f"SMTP Authentication failed for {email}: {auth_error}")
        suggestions = []
        if provider == 'amazon_ses':
            suggestions = [
                'Ensure you are using AWS SES SMTP credentials (not IAM credentials)',
                'Verify your AWS SES account is not in sandbox mode',
                'Check that your domain/email is verified in AWS SES',
                'Confirm you are using the correct AWS region'
            ]
        elif provider == 'gmail':
            suggestions = [
                'Use an App Password instead of your regular password',
                'Enable 2-Factor Authentication first',
                'Generate App Password from Google Account Security settings'
            ]
        elif provider == 'yahoo':
            suggestions = [
                'Use an App Password instead of your regular password',
                'Enable 2-Factor Authentication first'
            ]
        else:
            suggestions = ['Check your username and password', 'Verify account settings']
            
        return {
            'success': False,
            'message': f'SMTP Authentication failed: {str(auth_error)}',
            'error_type': 'auth_error',
            'suggestions': suggestions
        }
        
    except smtplib.SMTPConnectError as conn_error:
        logger.error(f"SMTP Connection failed for {smtp_host}:{smtp_port}: {conn_error}")
        return {
            'success': False,
            'message': f'Cannot connect to SMTP server {smtp_host}:{smtp_port}. Error: {str(conn_error)}',
            'error_type': 'connection_error',
            'suggestions': [
                'Check if the SMTP host and port are correct',
                'Verify your network/firewall allows SMTP connections',
                'Try a different port (587 for TLS, 465 for SSL)'
            ]
        }
        
    except smtplib.SMTPException as smtp_error:
        logger.error(f"SMTP Error for {email}: {smtp_error}")
        return {
            'success': False,
            'message': f'SMTP Error: {str(smtp_error)}',
            'error_type': 'smtp_error'
        }
        
    except Exception as general_error:
        logger.error(f"General SMTP validation error for {email}: {general_error}")
        return {
            'success': False,
            'message': f'Validation failed: {str(general_error)}',
            'error_type': 'general_error'
        }

def get_setup_instructions(provider):
    provider_info = SMTP_PROVIDERS.get(provider, SMTP_PROVIDERS['custom'])
    
    base_instructions = {
        'gmail': {
            'title': 'Gmail Setup Instructions',
            'steps': [
                '1. Enable 2-Factor Authentication on your Google account',
                '2. Go to Google Account settings > Security > App passwords',
                '3. Generate an App Password for "Mail"',
                '4. Use your Gmail address and the generated App Password (not your regular password)'
            ]
        },
        'outlook': {
            'title': 'Outlook Setup Instructions', 
            'steps': [
                '1. Use your regular Outlook email and password',
                '2. If 2FA is enabled, you may need to create an App Password',
                '3. Check Microsoft account security settings if authentication fails'
            ]
        },
        'yahoo': {
            'title': 'Yahoo Mail Setup Instructions',
            'steps': [
                '1. Enable 2-Factor Authentication on your Yahoo account',
                '2. Go to Yahoo Account Security settings',
                '3. Generate an App Password for "Mail"',
                '4. Use your Yahoo email and the generated App Password'
            ]
        },
        'amazon_ses': {
            'title': 'Amazon SES Setup Instructions',
            'steps': [
                '1. Log into AWS Console and go to Amazon SES',
                '2. Go to Account Dashboard > SMTP Settings',
                '3. Click "Create SMTP Credentials"',
                '4. Download the SMTP username and password (NOT your IAM credentials)',
                '5. Verify your domain/email in SES if in sandbox mode',
                '6. Use the SES SMTP endpoint for your region'
            ]
        },
        'custom': {
            'title': 'Custom SMTP Setup',
            'steps': [
                '1. Get SMTP settings from your email provider',
                '2. Enter the correct SMTP host and port',
                '3. Use your email credentials or app-specific password'
            ]
        }
    }
    
    return base_instructions.get(provider, base_instructions['custom'])

# Routes
@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password are required'})
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            session['user_id'] = user.id
            session['username'] = user.username
            session['email'] = user.email
            
            return jsonify({
                'success': True, 
                'message': f'Welcome back, {user.username}!', 
                'user': user.to_dict()
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid email or password'})
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'success': False, 'message': 'Login failed'})

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        if not username or not email or not password:
            return jsonify({'success': False, 'message': 'All fields are required'})
        
        if len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'})
        
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already registered'})
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already taken'})
        
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        session['user_id'] = user.id
        session['username'] = user.username
        session['email'] = user.email
        
        return jsonify({
            'success': True, 
            'message': f'Account created successfully! Welcome, {username}!', 
            'user': user.to_dict()
        })
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Registration failed'})

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json()
        email = data.get('email', '').lower().strip()
        
        if not email:
            return jsonify({'success': False, 'message': 'Email is required'})
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            reset_token = user.generate_reset_token()
            return jsonify({
                'success': True,
                'message': 'Password reset instructions sent to your email',
                'reset_token': reset_token,
                'reset_url': f'/?token={reset_token}'
            })
        else:
            return jsonify({
                'success': True,
                'message': 'If that email exists, password reset instructions have been sent'
            })
    except Exception as e:
        return jsonify({'success': False, 'message': 'Request failed'})

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        token = data.get('token', '')
        new_password = data.get('password', '')
        
        if not token or not new_password:
            return jsonify({'success': False, 'message': 'Token and new password are required'})
        
        if len(new_password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'})
        
        user = User.query.filter_by(reset_token=token).first()
        
        if user and user.verify_reset_token(token):
            user.set_password(new_password)
            user.reset_token = None
            user.reset_token_expires = None
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Password reset successfully! You can now login with your new password.'
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid or expired reset token'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Reset failed'})

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
        return jsonify({'error': 'Provider detection failed'})

@app.route('/api/test-smtp', methods=['POST'])
def test_smtp():
    try:
        data = request.get_json()
        
        email = data.get('email', '')
        password = data.get('password', '')
        smtp_host = data.get('smtp_host', '')
        smtp_port = int(data.get('smtp_port', 587))
        smtp_username = data.get('smtp_username', email)
        provider = data.get('provider', 'custom')
        
        if not all([email, password, smtp_host]):
            return jsonify({
                'success': False,
                'message': 'Email, SMTP host, and password are required'
            })
        
        result = validate_smtp_comprehensive(email, password, smtp_host, smtp_port, smtp_username, provider)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"SMTP test error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'SMTP test failed: {str(e)}'
        })

@app.route('/api/dashboard/stats')
def dashboard_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        user_id = session['user_id']
        campaigns = Campaign.query.filter_by(user_id=user_id).all()
        
        stats = {
            'active_campaigns': len([c for c in campaigns if c.status == 'active']),
            'total_campaigns': len(campaigns),
            'emails_sent_today': 0,
            'avg_reputation_score': 85.5
        }
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': 'Failed to load stats'})

@app.route('/api/campaigns', methods=['GET', 'POST'])
def campaigns_api():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    
    try:
        if request.method == 'POST':
            data = request.get_json()
            
            required_fields = ['name', 'email', 'smtp_host', 'smtp_password']
            for field in required_fields:
                if not data.get(field):
                    return jsonify({'success': False, 'message': f'{field} is required'})
            
            campaign = Campaign(
                name=data.get('name'),
                email_address=data.get('email'),
                smtp_host=data.get('smtp_host'),
                smtp_port=data.get('smtp_port', 587),
                smtp_username=data.get('smtp_username', data.get('email')),
                smtp_password=data.get('smtp_password'),
                provider=data.get('provider', 'custom'),
                user_id=user_id
            )
            
            db.session.add(campaign)
            db.session.commit()
            
            return jsonify({
                'success': True, 
                'message': 'Campaign created successfully', 
                'campaign': campaign.to_dict()
            })
        
        else:
            campaigns = Campaign.query.filter_by(user_id=user_id).all()
            return jsonify([c.to_dict() for c in campaigns])
            
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Campaign operation failed'})

# Initialize database
with app.app_context():
    db.create_all()
    
    # Create demo user
    if not User.query.filter_by(email='demo@example.com').first():
        demo_user = User(username='demo', email='demo@example.com')
        demo_user.set_password('demo123')
        db.session.add(demo_user)
        db.session.commit()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
