#!/bin/bash

# Email Warmup System - Quick Start Script

echo "🚀 Email Warmup System - Quick Start"
echo "====================================="

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    echo "Please install Python 3.7+ and try again."
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is required but not installed."
    echo "Please install pip3 and try again."
    exit 1
fi

echo "✅ Python and pip found"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install -r requirements.txt

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "⚙️  Creating environment configuration..."
    cp .env.example .env
    echo "📝 Please edit .env file with your settings before running the application."
fi

# Initialize database
echo "🗄️  Initializing database..."
python -c "from app import app, db; app.app_context().push(); db.create_all(); print('Database initialized successfully!')"

echo ""
echo "🎉 Setup complete!"
echo ""
echo "To start the application:"
echo "1. Edit the .env file with your configuration"
echo "2. Run: python app.py"
echo "3. Open http://localhost:5000 in your browser"
echo ""
echo "For production deployment:"
echo "- Railway: Use the included railway.json"
echo "- Docker: Run 'docker-compose up'"
echo "- Manual: Run 'gunicorn app:app'"
echo ""
echo "📚 See README.md for detailed documentation"
