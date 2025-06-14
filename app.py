import os
import logging
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json
import secrets
from apscheduler.schedulers.background import BackgroundScheduler
import atexit

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///warmup.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
cors = CORS(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import models and routes after app initialization
from models.models import User, Campaign, EmailLog, WarmupAccount
from routes.api import api_bp
from routes.campaigns import campaigns_bp
from services.warmup_service import WarmupService

# Register blueprints
app.register_blueprint(api_bp, url_prefix='/api')
app.register_blueprint(campaigns_bp, url_prefix='/api/campaigns')

# Initialize warmup service
warmup_service = WarmupService()

# Main dashboard route
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

# Create tables
with app.app_context():
    db.create_all()
    logger.info("Database tables created")

# Background scheduler for warmup tasks
scheduler = BackgroundScheduler()
scheduler.add_job(
    func=warmup_service.run_scheduled_warmup,
    trigger="interval",
    minutes=30,
    id='warmup_job'
)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)
