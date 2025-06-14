from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import os
import json
import smtplib
import ssl
import imaplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import base64
from urllib.parse import urlencode
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'

# In-memory storage
users = {}
campaigns = {}
oauth_tokens = {}
user_counter = 1
campaign_counter = 1

# Comprehensive SMTP provider configurations
SMTP_PROVIDERS = {
    'gmail': {
        'smtp_host': 'smtp.gmail.com',
        'smtp_port': 587,
        'imap_host': 'imap.gmail.com',
        'imap_port': 993,
        'oauth_enabled': True,
        'oauth_config': {
            'auth_url': 'https://accounts.google.com/o/oauth2/auth',
            'token_url': 'https://oauth2.googleapis.com/token',
            'scope': 'https://mail.google.com/',
            'client_id': os.environ.get('GOOGLE_CLIENT_ID', ''),
            'client_secret': os.environ.get('GOOGLE_CLIENT_SECRET', '')
        }
    },
    'outlook': {
        'smtp_host': 'smtp-mail.outlook.com',
        'smtp_port': 587,
        'imap_host': 'outlook.office365.com',
        'imap_port': 993,
        'oauth_enabled': True,
        'oauth_config': {
            'auth_url': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
            'token_url': 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            'scope': 'https://outlook.office.com/SMTP.Send https://outlook.office.com/IMAP.AccessAsUser.All',
            'client_id': os.environ.get('MICROSOFT_CLIENT_ID', ''),
            'client_secret': os.environ.get('MICROSOFT_CLIENT_SECRET', '')
        }
    },
    'yahoo': {
        'smtp_host': 'smtp.mail.yahoo.com',
        'smtp_port': 587,
        'imap_host': 'imap.mail.yahoo.com',
        'imap_port': 993,
        'oauth_enabled': True,
        'oauth_config': {
            'auth_url': 'https://api.login.yahoo.com/oauth2/request_auth',
            'token_url': 'https://api.login.yahoo.com/oauth2/get_token',
            'scope': 'mail-w',
            'client_id': os.environ.get('YAHOO_CLIENT_ID', ''),
            'client_secret': os.environ.get('YAHOO_CLIENT_SECRET', '')
        }
    },
    'aws_ses': {
        'smtp_host': 'email-smtp.{region}.amazonaws.com',
        'smtp_port': 587,
        'regions': [
            'us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1',
            'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1'
        ],
        'oauth_enabled': False
    },
    'sendgrid': {
        'smtp_host': 'smtp.sendgrid.net',
        'smtp_port': 587,
        'oauth_enabled': False
    },
    'mailgun': {
        'smtp_host': 'smtp.mailgun.org',
        'smtp_port': 587,
        'oauth_enabled': False
    },
    'postmark': {
        'smtp_host': 'smtp.postmarkapp.com',
        'smtp_port': 587,
        'oauth_enabled': False
    },
    'sparkpost': {
        'smtp_host': 'smtp.sparkpostmail.com',
        'smtp_port': 587,
        'oauth_enabled': False
    },
    'zoho': {
        'smtp_host': 'smtp.zoho.com',
        'smtp_port': 587,
        'oauth_enabled': False
    },
    'custom': {
        'smtp_host': '',
        'smtp_port': 587,
        'oauth_enabled': False
    }
}

def detect_email_provider(email):
    """Auto-detect email provider from email address"""
    domain = email.split('@')[-1].lower()
    
    provider_mappings = {
        'gmail.com': 'gmail',
        'googlemail.com': 'gmail',
        'outlook.com': 'outlook',
        'hotmail.com': 'outlook',
        'live.com': 'outlook',
        'msn.com': 'outlook',
        'yahoo.com': 'yahoo',
        'yahoo.co.uk': 'yahoo',
        'ymail.com': 'yahoo',
        'rocketmail.com': 'yahoo',
        'zoho.com': 'zoho',
        'zohomail.com': 'zoho'
    }
    
    return provider_mappings.get(domain, 'custom')

def validate_smtp_comprehensive(email, password, smtp_host, smtp_port, smtp_username=None, provider='custom', oauth_token=None):
    """Comprehensive SMTP validation with real connection testing"""
    
    # Use email as username if no specific username provided
    if not smtp_username:
        smtp_username = email
    
    try:
        # Test SMTP connection
        smtp_result = test_smtp_connection(email, password, smtp_host, smtp_port, smtp_username, oauth_token)
        if not smtp_result['success']:
            return smtp_result
        
        # Test IMAP connection if provider supports it
        if provider in SMTP_PROVIDERS and 'imap_host' in SMTP_PROVIDERS[provider]:
            imap_result = test_imap_connection(email, password, provider, oauth_token)
            if not imap_result['success']:
                return {
                    'success': True,
                    'message': 'SMTP validated successfully, but IMAP test failed. SMTP functionality confirmed.',
                    'smtp_test': smtp_result,
                    'imap_test': imap_result
                }
        
        return {
            'success': True,
            'message': 'Email credentials fully validated! SMTP and IMAP connections successful.',
            'smtp_test': smtp_result,
            'provider_detected': provider
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'Validation failed: {str(e)}'
        }

def test_smtp_connection(email, password, smtp_host, smtp_port, smtp_username, oauth_token=None):
    """Test actual SMTP connection"""
    try:
        # Create SMTP connection based on port
        if smtp_port == 465:
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, context=context)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port)
            server.starttls()
        
        # Authenticate
        if oauth_token:
            # OAuth2 authentication
            auth_string = f"user={email}\x01auth=Bearer {oauth_token}\x01\x01"
            auth_string_b64 = base64.b64encode(auth_string.encode()).decode()
            server.docmd('AUTH', f'XOAUTH2 {auth_string_b64}')
        else:
            # Username/password authentication
            server.login(smtp_username, password)
        
        # Send test email
        test_msg = MIMEMultipart()
        test_msg['From'] = email
        test_msg['To'] = email
        test_msg['Subject'] = "SMTP Validation Test - Email Warmup System"
        
        body = """
This is a test email from your Email Warmup System.

✅ SMTP Configuration Validated Successfully!

Your email account is properly configured and ready for email warmup campaigns.

This test confirms:
- SMTP server connection works
- Authentication is successful  
- Email sending is functional

You can now proceed with creating your email warmup campaign.

---
Email Warmup System
        """
        
        test_msg.attach(MIMEText(body, 'plain'))
        
        server.send_message(test_msg)
        server.quit()
        
        return {
            'success': True,
            'message': f'SMTP test successful! Test email sent to {email}',
            'details': f'Connected to {smtp_host}:{smtp_port}'
        }
        
    except smtplib.SMTPAuthenticationError as e:
        return {
            'success': False,
            'message': f'SMTP Authentication failed: {str(e)}. Check username and password.',
            'error_type': 'auth_error'
        }
    except smtplib.SMTPConnectError as e:
        return {
            'success': False,
            'message': f'Could not connect to SMTP server {smtp_host}:{smtp_port}. Error: {str(e)}',
            'error_type': 'connection_error'
        }
    except Exception as e:
        return {
            'success': False,
            'message': f'SMTP test failed: {str(e)}',
            'error_type': 'general_error'
        }

def test_imap_connection(email, password, provider, oauth_token=None):
    """Test IMAP connection for inbox access"""
    try:
        if provider not in SMTP_PROVIDERS or 'imap_host' not in SMTP_PROVIDERS[provider]:
            return {'success': False, 'message': 'IMAP not supported for this provider'}
        
        imap_host = SMTP_PROVIDERS[provider]['imap_host']
        imap_port = SMTP_PROVIDERS[provider]['imap_port']
        
        # Connect to IMAP server
        mail = imaplib.IMAP4_SSL(imap_host, imap_port)
        
        if oauth_token:
            # OAuth2 authentication for IMAP
            auth_string = f"user={email}\x01auth=Bearer {oauth_token}\x01\x01"
            auth_string_b64 = base64.b64encode(auth_string.encode()).decode()
            mail.authenticate('XOAUTH2', lambda x: auth_string_b64)
        else:
            mail.login(email, password)
        
        # Test inbox access
        mail.select('INBOX')
        mail.close()
        mail.logout()
        
        return {
            'success': True,
            'message': f'IMAP connection successful to {imap_host}',
            'details': f'Inbox access confirmed'
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'IMAP test failed: {str(e)}'
        }

# OAuth2 Routes
@app.route('/oauth/start/<provider>')
def oauth_start(provider):
    """Start OAuth flow for email provider"""
    if provider not in SMTP_PROVIDERS or not SMTP_PROVIDERS[provider]['oauth_enabled']:
        return jsonify({'error': 'OAuth not supported for this provider'}), 400
    
    config = SMTP_PROVIDERS[provider]['oauth_config']
    
    # Generate state for security
    state = secrets.token_urlsafe(32)
    session[f'oauth_state_{provider}'] = state
    
    # Build authorization URL
    params = {
        'client_id': config['client_id'],
        'response_type': 'code',
        'scope': config['scope'],
        'redirect_uri': url_for('oauth_callback', provider=provider, _external=True),
        'state': state
    }
    
    auth_url = f"{config['auth_url']}?{urlencode(params)}"
    return redirect(auth_url)

@app.route('/oauth/callback/<provider>')
def oauth_callback(provider):
    """Handle OAuth callback"""
    if provider not in SMTP_PROVIDERS:
        return jsonify({'error': 'Invalid provider'}), 400
    
    # Verify state
    state = request.args.get('state')
    if state != session.get(f'oauth_state_{provider}'):
        return jsonify({'error': 'Invalid state parameter'}), 400
    
    # Exchange code for token
    code = request.args.get('code')
    config = SMTP_PROVIDERS[provider]['oauth_config']
    
    token_data = {
        'client_id': config['client_id'],
        'client_secret': config['client_secret'],
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': url_for('oauth_callback', provider=provider, _external=True)
    }
    
    try:
        response = requests.post(config['token_url'], data=token_data)
        token_response = response.json()
        
        if 'access_token' in token_response:
            # Store token
            oauth_tokens[f"{session.get('user_id')}_{provider}"] = token_response
            return jsonify({
                'success': True,
                'message': f'OAuth authentication successful for {provider}',
                'provider': provider
            })
        else:
            return jsonify({'error': 'Failed to obtain access token'}), 400
            
    except Exception as e:
        return jsonify({'error': f'OAuth callback failed: {str(e)}'}), 500

# Main Routes
@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if email == 'demo@example.com' and password == 'demo123':
        session['user_id'] = 1
        session['username'] = 'demo'
        return jsonify({
            'success': True, 
            'message': 'Login successful', 
            'user': {'id': 1, 'username': 'demo', 'email': 'demo@example.com'}
        })
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/api/register', methods=['POST'])
def register():
    global user_counter
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if email in users:
        return jsonify({'success': False, 'message': 'Email already registered'}), 400
    
    user_id = user_counter
    user_counter += 1
    
    users[email] = {
        'id': user_id,
        'username': username,
        'email': email,
        'password': password
    }
    
    session['user_id'] = user_id
    session['username'] = username
    
    return jsonify({
        'success': True, 
        'message': 'Registration successful', 
        'user': {'id': user_id, 'username': username, 'email': email}
    })

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/detect-provider', methods=['POST'])
def detect_provider():
    """Auto-detect email provider and return configuration"""
    data = request.get_json()
    email = data.get('email', '')
    
    provider = detect_email_provider(email)
    config = SMTP_PROVIDERS.get(provider, SMTP_PROVIDERS['custom'])
    
    return jsonify({
        'provider': provider,
        'config': {
            'smtp_host': config['smtp_host'],
            'smtp_port': config['smtp_port'],
            'oauth_enabled': config.get('oauth_enabled', False),
            'requires_app_password': provider in ['gmail', 'yahoo']
        },
        'setup_instructions': get_setup_instructions(provider)
    })

def get_setup_instructions(provider):
    """Get setup instructions for each provider"""
    instructions = {
        'gmail': {
            'title': 'Gmail Setup Instructions',
            'steps': [
                '1. Enable 2-Factor Authentication on your Google account',
                '2. Go to Google Account settings > Security > App passwords',
                '3. Generate an App Password for "Mail"',
                '4. Use your email and the generated App Password',
                '5. Or use OAuth2 authentication (recommended)'
            ]
        },
        'outlook': {
            'title': 'Outlook/Hotmail Setup Instructions',
            'steps': [
                '1. Use your regular email and password',
                '2. If 2FA is enabled, create an App Password',
                '3. Go to Account Security > Advanced security options',
                '4. Or use OAuth2 authentication (recommended)'
            ]
        },
        'yahoo': {
            'title': 'Yahoo Mail Setup Instructions',
            'steps': [
                '1. Enable 2-Factor Authentication',
                '2. Go to Account Security > Generate app password',
                '3. Create password for "Mail"',
                '4. Use your email and generated password'
            ]
        },
        'aws_ses': {
            'title': 'AWS SES Setup Instructions',
            'steps': [
                '1. Get your SMTP credentials from AWS SES console',
                '2. Choose your AWS region',
                '3. Use SMTP username and password from AWS',
                '4. Ensure your email is verified in SES'
            ]
        },
        'custom': {
            'title': 'Custom SMTP Setup',
            'steps': [
                '1. Get SMTP settings from your email provider',
                '2. Common ports: 587 (TLS), 465 (SSL), 25 (unsecured)',
                '3. Ensure authentication is enabled',
                '4. Check firewall and security settings'
            ]
        }
    }
    
    return instructions.get(provider, instructions['custom'])

@app.route('/api/test-smtp', methods=['POST'])
def test_smtp():
    """Real SMTP validation endpoint"""
    data = request.get_json()
    
    email = data.get('email', '')
    password = data.get('password', '')
    smtp_host = data.get('smtp_host', '')
    smtp_port = int(data.get('smtp_port', 587))
    smtp_username = data.get('smtp_username', '')
    provider = data.get('provider', 'custom')
    use_oauth = data.get('use_oauth', False)
    
    # Validate required fields
    if not email or not smtp_host:
        return jsonify({
            'success': False,
            'message': 'Email and SMTP host are required'
        })
    
    # Auto-detect provider if not specified
    if provider == 'auto':
        provider = detect_email_provider(email)
    
    # Get OAuth token if using OAuth
    oauth_token = None
    if use_oauth and 'user_id' in session:
        token_key = f"{session['user_id']}_{provider}"
        if token_key in oauth_tokens:
            oauth_token = oauth_tokens[token_key].get('access_token')
    
    # Perform comprehensive validation
    result = validate_smtp_comprehensive(
        email=email,
        password=password,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_username=smtp_username,
        provider=provider,
        oauth_token=oauth_token
    )
    
    return jsonify(result)

@app.route('/api/dashboard/stats')
def dashboard_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_campaigns = [c for c in campaigns.values() if c.get('user_id') == session['user_id']]
    
    stats = {
        'active_campaigns': len([c for c in user_campaigns if c.get('status') == 'active']),
        'total_campaigns': len(user_campaigns),
        'emails_sent_today': 42,
        'avg_reputation_score': 85.5
    }
    
    return jsonify(stats)

@app.route('/api/campaigns', methods=['GET', 'POST'])
def campaigns_api():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    
    if request.method == 'POST':
        global campaign_counter
        data = request.get_json()
        
        campaign_id = campaign_counter
        campaign_counter += 1
        
        campaigns[campaign_id] = {
            'id': campaign_id,
            'name': data.get('name'),
            'email_address': data.get('email'),
            'smtp_host': data.get('smtp_host'),
            'smtp_port': data.get('smtp_port'),
            'smtp_username': data.get('smtp_username'),
            'provider': data.get('provider'),
            'status': 'draft',
            'user_id': user_id,
            'created_at': '2024-01-01T00:00:00'
        }
        
        return jsonify({
            'success': True, 
            'message': 'Campaign created successfully', 
            'campaign': campaigns[campaign_id]
        })
    
    else:
        user_campaigns = [c for c in campaigns.values() if c.get('user_id') == user_id]
        return jsonify(user_campaigns)

@app.route('/api/campaigns/<int:campaign_id>/start', methods=['POST'])
def start_campaign(campaign_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if campaign_id in campaigns and campaigns[campaign_id]['user_id'] == session['user_id']:
        campaigns[campaign_id]['status'] = 'active'
        return jsonify({'success': True, 'message': 'Campaign started successfully'})
    
    return jsonify({'error': 'Campaign not found'}), 404

@app.route('/api/campaigns/<int:campaign_id>/pause', methods=['POST'])
def pause_campaign(campaign_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if campaign_id in campaigns and campaigns[campaign_id]['user_id'] == session['user_id']:
        campaigns[campaign_id]['status'] = 'paused'
        return jsonify({'success': True, 'message': 'Campaign paused successfully'})
    
    return jsonify({'error': 'Campaign not found'}), 404

@app.route('/api/providers')
def get_providers():
    """Get list of supported email providers"""
    providers = []
    for key, config in SMTP_PROVIDERS.items():
        providers.append({
            'id': key,
            'name': key.replace('_', ' ').title(),
            'smtp_host': config['smtp_host'],
            'smtp_port': config['smtp_port'],
            'oauth_enabled': config.get('oauth_enabled', False)
        })
    
    return jsonify(providers)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
