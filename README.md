# Email Warmup System

A comprehensive email warmup platform built with Flask that helps improve email deliverability by gradually building sender reputation through automated email exchanges.

## Features

✅ **Real-time SMTP Validation** - Validates email credentials before campaign creation
✅ **Progressive Volume Scaling** - Gradually increases email volume from 5 to 100+ emails/day
✅ **Multi-Provider Support** - Works with Gmail, Outlook, Yahoo, and custom SMTP servers
✅ **Automated Conversations** - Creates realistic email exchanges with temporary accounts
✅ **Campaign Management** - Full control over warmup campaigns (start, pause, stop)
✅ **Real-time Dashboard** - Monitor progress with detailed analytics
✅ **Encrypted Credentials** - Secure storage of email passwords
✅ **Background Processing** - Automated warmup cycles using Celery
✅ **Industry Templates** - Customized content for different business sectors
✅ **Responsive UI** - Beautiful dashboard with TailwindCSS

## Quick Start

### Option 1: Local Development

1. **Clone and Setup**
   ```bash
   git clone <repository-url>
   cd email_warmup_system
   pip install -r requirements.txt
   ```

2. **Environment Configuration**
   ```bash
   cp .env.example .env
   # Edit .env file with your settings
   ```

3. **Initialize Database**
   ```bash
   python -c "from app import app, db; app.app_context().push(); db.create_all()"
   ```

4. **Run the Application**
   ```bash
   python app.py
   ```

   Visit http://localhost:5000 to access the dashboard.

### Option 2: Docker Deployment

1. **Using Docker Compose**
   ```bash
   docker-compose up -d
   ```

2. **Access Application**
   - Web Interface: http://localhost:5000
   - Redis: localhost:6379

### Option 3: Railway Cloud Deployment

1. **Deploy to Railway**
   [![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/your-template)

2. **Set Environment Variables**
   - `SECRET_KEY`: Your secret key for Flask sessions
   - `ENCRYPTION_KEY`: Key for encrypting email passwords
   - `DATABASE_URL`: Automatically provided by Railway

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_ENV` | Environment (development/production) | development |
| `SECRET_KEY` | Flask secret key | dev-secret-key |
| `DATABASE_URL` | Database connection string | sqlite:///warmup.db |
| `ENCRYPTION_KEY` | Email password encryption key | auto-generated |
| `REDIS_URL` | Redis connection for Celery | redis://localhost:6379/0 |
| `PORT` | Application port | 5000 |

### SMTP Providers

The system supports multiple email providers:

- **Gmail**: Requires App Password (2FA must be enabled)
- **Outlook/Hotmail**: Requires App Password
- **Yahoo**: Requires App Password
- **Custom SMTP**: Any SMTP server with authentication

## How It Works

### 1. Campaign Creation
- Enter email credentials (validated in real-time)
- Choose industry for appropriate content templates
- Set volume limits and duration (default: 5-100 emails/day over 30 days)

### 2. Warmup Process
- System creates 5-10 temporary email accounts
- Starts with low volume (5 emails/day)
- Gradually increases volume every 3 days
- Generates natural conversation threads
- Tracks deliverability and engagement metrics

### 3. Monitoring
- Real-time dashboard with campaign statistics
- Progress tracking with visual indicators
- Email logs and conversation history
- Deliverability scoring and recommendations

## API Endpoints

### Authentication
- `POST /api/register` - User registration
- `POST /api/login` - User login
- `POST /api/logout` - User logout

### SMTP Validation
- `POST /api/validate-smtp` - Validate email credentials

### Campaigns
- `GET /api/campaigns/` - List all campaigns
- `POST /api/campaigns/` - Create new campaign
- `GET /api/campaigns/<id>` - Get campaign details
- `PUT /api/campaigns/<id>` - Update campaign
- `DELETE /api/campaigns/<id>` - Delete campaign
- `POST /api/campaigns/<id>/start` - Start campaign
- `POST /api/campaigns/<id>/pause` - Pause campaign
- `POST /api/campaigns/<id>/stop` - Stop campaign

### Analytics
- `GET /api/dashboard-stats` - Dashboard statistics
- `GET /api/campaigns/<id>/logs` - Campaign email logs

## Security Features

- **Credential Encryption**: Email passwords encrypted using Fernet
- **Session Management**: Secure session handling with Flask
- **Rate Limiting**: API rate limiting to prevent abuse
- **CSRF Protection**: Cross-site request forgery protection
- **Input Validation**: Comprehensive input validation and sanitization

## Email Provider Setup

### Gmail Setup
1. Enable 2-Factor Authentication
2. Go to Google Account → Security → 2-Step Verification
3. Generate App Password for "Mail"
4. Use Gmail address + App Password in the system

### Outlook Setup
1. Enable 2-Factor Authentication
2. Go to Microsoft Account → Security
3. Generate App Password
4. Use Outlook address + App Password in the system

### Yahoo Setup
1. Enable 2-Factor Authentication
2. Go to Yahoo Account Security
3. Generate App Password for "Desktop app"
4. Use Yahoo address + App Password in the system

## Development

### Project Structure
```
email_warmup_system/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── Procfile              # Railway/Heroku deployment
├── railway.json          # Railway configuration
├── docker-compose.yml    # Docker composition
├── .env.example          # Environment variables template
├── models/
│   └── models.py         # Database models
├── routes/
│   ├── api.py           # API endpoints
│   └── campaigns.py     # Campaign routes
├── services/
│   └── warmup_service.py # Email warmup logic
├── utils/
│   └── smtp_validator.py # SMTP validation
├── templates/
│   └── dashboard.html    # Frontend dashboard
├── static/
│   └── js/
│       └── dashboard.js  # Frontend JavaScript
└── config/
    └── config.py        # Application configuration
```

### Adding New Features

1. **Models**: Add new database models in `models/models.py`
2. **API Routes**: Add new endpoints in `routes/`
3. **Business Logic**: Add services in `services/`
4. **Frontend**: Update `templates/dashboard.html` and `static/js/dashboard.js`

### Testing

Run tests with:
```bash
python -m pytest tests/
```

## Troubleshooting

### Common Issues

1. **SMTP Authentication Failed**
   - Ensure 2FA is enabled
   - Use App Password, not regular password
   - Check provider-specific settings

2. **Database Issues**
   - Ensure database is initialized: `python -c "from app import app, db; app.app_context().push(); db.create_all()"`
   - Check DATABASE_URL environment variable

3. **Redis Connection Issues**
   - Ensure Redis is running: `redis-server`
   - Check REDIS_URL environment variable

4. **Port Already in Use**
   - Change PORT environment variable
   - Kill existing processes: `lsof -ti:5000 | xargs kill -9`

### Logs

Check application logs for debugging:
```bash
# Development
python app.py

# Production
gunicorn app:app --log-level info
```

## Production Deployment

### Security Checklist
- [ ] Set strong SECRET_KEY
- [ ] Set unique ENCRYPTION_KEY
- [ ] Use PostgreSQL database
- [ ] Configure Redis with authentication
- [ ] Set up HTTPS
- [ ] Configure proper CORS settings
- [ ] Set up monitoring and logging

### Scaling
- Use multiple worker processes: `gunicorn app:app --workers 4`
- Implement horizontal scaling with load balancer
- Use dedicated Redis instance for production
- Consider database connection pooling

## Support

For issues and feature requests, please create an issue in the repository.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Note**: This system is designed for legitimate email warmup purposes. Always follow email provider terms of service and anti-spam regulations.
