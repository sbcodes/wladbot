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

def init_db():
    load_dotenv()
    
    # Get database URL from environment variable
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        print("Error: DATABASE_URL environment variable not set.")
        print("Please set the DATABASE_URL in your .env file or environment.")
        print("Example: DATABASE_URL=postgresql://username:password@localhost/dbname")
        sys.exit(1)
    
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
            print(f"Created database at {database_url}")
        
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

if __name__ == "__main__":
    init_db() 