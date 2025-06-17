#!/usr/bin/env python3
import os
from app import app, create_tables

if __name__ == '__main__':
    try:
        # Initialize database
        create_tables()
        port = int(os.environ.get('PORT', 5000))
        app.run(host='0.0.0.0', port=port, debug=False)
    except Exception as e:
        print(f"Startup error: {e}")
        # Try without database initialization
        port = int(os.environ.get('PORT', 5000))
        app.run(host='0.0.0.0', port=port, debug=False)
