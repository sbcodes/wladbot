#!/usr/bin/env python
"""
Script to initialize the PostgreSQL database for the chat application
"""
import os
import sys
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy_utils import database_exists, create_database
from models import db, Message
from flask import Flask
import urllib.parse
import re

def fix_database_url(url):
    """Properly parse and fix a PostgreSQL connection URL with special characters"""
    try:
        # Extract components using regex to avoid splitting problems
        match = re.match(r'postgresql://([^:]+):([^@]+)@([^/]+)/(.+)', url)
        if not match:
            print(f"Warning: Could not parse DATABASE_URL format: {url[:10]}...")
            return url
        
        username, password, host, dbname = match.groups()
        
        # URL encode the password
        encoded_password = urllib.parse.quote_plus(password)
        
        # Reconstruct the URL
        fixed_url = f"postgresql://{username}:{encoded_password}@{host}/{dbname}"
        
        # Print diagnostic info without exposing actual password
        print(f"Original URL pattern: postgresql://{username}:****@{host}/{dbname}")
        print(f"Fixed URL pattern: postgresql://{username}:****@{host}/{dbname}")
        print(f"Password encoding changed: {'Yes' if password != encoded_password else 'No'}")
        
        return fixed_url
    except Exception as e:
        print(f"Warning: Error fixing DATABASE_URL: {e}")
        return url

def init_db():
    load_dotenv()
    
    # Get database URL from environment variable
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        print("Error: DATABASE_URL environment variable not set.")
        print("Please set the DATABASE_URL in your .env file or environment.")
        print("Example: DATABASE_URL=postgresql://username:password@localhost/dbname")
        sys.exit(1)
    
    # Fix the database URL
    database_url = fix_database_url(database_url)
    
    try:
        # Create a minimal Flask app just for database initialization
        app = Flask(__name__)
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        
        # Initialize the app with the extension
        db.init_app(app)
        
        with app.app_context():
            # Check if database exists, if not create it
            engine = create_engine(database_url)
            if not database_exists(engine.url):
                create_database(engine.url)
                host = database_url.split('@')[1].split('/')[0]
                dbname = database_url.split('/')[-1]
                print(f"Created database at {host}/{dbname}")
            
            # Create tables
            db.create_all()
            print("Database tables created successfully!")
            
            # Check if Message table is empty, add a test message if it is
            if Message.query.count() == 0:
                test_message = Message(
                    content="Welcome to the chat! This is the first message.",
                    username="System"
                )
                db.session.add(test_message)
                db.session.commit()
                print("Added test message to database")
            
            print("Database initialization complete.")
    except Exception as e:
        print(f"Error initializing database: {e}")
        sys.exit(1)

if __name__ == "__main__":
    init_db() 