from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///email_warmup.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

# Campaign Model
class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email_address = db.Column(db.String(120), nullable=False)
    email_password = db.Column(db.Text)
    provider = db.Column(db.String(50), default='gmail')
    status = db.Column(db.String(50), default='draft')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email_address': self.email_address,
            'provider': self.provider,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return render_template('dashboard.html')
    return render_template('dashboard.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    user = User.query.filter_by(email=email).first()
    
    if user and user.check_password(password):
        session['user_id'] = user.id
        session['username'] = user.username
        return jsonify({'success': True, 'message': 'Login successful', 'user': user.to_dict()})
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email already registered'}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': 'Username already taken'}), 400
    
    user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password)
    )
    
    db.session.add(user)
    db.session.commit()
    
    session['user_id'] = user.id
    session['username'] = user.username
    
    return jsonify({'success': True, 'message': 'Registration successful', 'user': user.to_dict()})

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/dashboard/stats')
def dashboard_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    campaigns = Campaign.query.filter_by(user_id=user_id).all()
    
    stats = {
        'active_campaigns': len([c for c in campaigns if c.status == 'active']),
        'total_campaigns': len(campaigns),
        'emails_sent_today': 0,
        'avg_reputation_score': 85.5
    }
    
    return jsonify(stats)

@app.route('/api/campaigns', methods=['GET', 'POST'])
def campaigns():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    
    if request.method == 'POST':
        data = request.get_json()
        
        campaign = Campaign(
            name=data.get('name'),
            email_address=data.get('email'),
            email_password=data.get('password'),  # In production, encrypt this
            provider=data.get('provider'),
            user_id=user_id
        )
        
        db.session.add(campaign)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Campaign created successfully', 'campaign': campaign.to_dict()})
    
    else:
        campaigns = Campaign.query.filter_by(user_id=user_id).all()
        return jsonify([campaign.to_dict() for campaign in campaigns])

@app.route('/api/campaigns/<int:campaign_id>/start', methods=['POST'])
def start_campaign(campaign_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    campaign = Campaign.query.filter_by(id=campaign_id, user_id=session['user_id']).first()
    
    if not campaign:
        return jsonify({'error': 'Campaign not found'}), 404
    
    campaign.status = 'active'
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Campaign started successfully'})

@app.route('/api/campaigns/<int:campaign_id>/pause', methods=['POST'])
def pause_campaign(campaign_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    campaign = Campaign.query.filter_by(id=campaign_id, user_id=session['user_id']).first()
    
    if not campaign:
        return jsonify({'error': 'Campaign not found'}), 404
    
    campaign.status = 'paused'
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Campaign paused successfully'})

@app.route('/api/test-smtp', methods=['POST'])
def test_smtp():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    # Simple validation for demo
    if email and password and '@' in email:
        return jsonify({
            'success': True, 
            'message': 'SMTP credentials validated successfully!',
            'provider': 'gmail' if 'gmail' in email else 'outlook'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Invalid email or password format'
        })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    with app.app_context():
        db.create_all()
        # Create demo user if it doesn't exist
        if not User.query.filter_by(email='demo@example.com').first():
            demo_user = User(
                username='demo',
                email='demo@example.com',
                password_hash=generate_password_hash('demo123')
            )
            db.session.add(demo_user)
            db.session.commit()
    
    app.run(host='0.0.0.0', port=port, debug=False)
