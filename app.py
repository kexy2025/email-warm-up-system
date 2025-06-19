#!/usr/bin/env python3

import os
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
app.config['SECRET_KEY'] = 'test-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///warmup.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Simple Campaign model
class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), default='created')
    emails_sent = db.Column(db.Integer, default=0)

class EmailLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    recipient = db.Column(db.String(255))
    status = db.Column(db.String(20))
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)

# ROUTES
@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/test')
def test_route():
    return jsonify({'status': 'working', 'timestamp': datetime.now().isoformat()})

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

@app.route('/api/campaigns')
def get_campaigns():
    try:
        campaigns = Campaign.query.all()
        return jsonify([{
            'id': c.id,
            'name': c.name,
            'email': c.email,
            'status': c.status,
            'emails_sent': c.emails_sent
        } for c in campaigns])
    except Exception as e:
        return jsonify([])

@app.route('/api/campaigns/<int:campaign_id>/start', methods=['POST'])
def start_campaign(campaign_id):
    try:
        campaign = Campaign.query.get(campaign_id)
        if campaign:
            campaign.status = 'active'
            db.session.commit()
            return jsonify({'success': True, 'message': 'Campaign started'})
        return jsonify({'success': False, 'message': 'Campaign not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/debug/create-test-data', methods=['POST'])
def create_test_data():
    try:
        # Create test campaign if doesn't exist
        if Campaign.query.count() == 0:
            campaign = Campaign(name='Test1', email='scott@getkexy.com', status='active', emails_sent=10)
            db.session.add(campaign)
            db.session.commit()
            
            # Create test email logs
            for i in range(10):
                log = EmailLog(campaign_id=campaign.id, recipient=f'test{i}@example.com', status='sent')
                db.session.add(log)
            db.session.commit()
            
        return jsonify({'success': True, 'message': 'Test data created'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# Initialize database on startup
def init_db():
    with app.app_context():
        db.create_all()
        logger.info("Database tables created")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    
    # Initialize database
    init_db()
    
    app.run(host='0.0.0.0', port=port, debug=False)
