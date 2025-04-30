from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from dotenv import load_dotenv
import os
import socket
import logging
import sys
import bcrypt
import json
from datetime import datetime
from models import db, Message
import random  # Add this import at the top of the file with other imports

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('app.log')
    ]
)
logger = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))  # Get from env var or generate

# Set up database
database_url = os.environ.get('DATABASE_URL')
if not database_url:
    logger.warning("DATABASE_URL not set! Using in-memory SQLite database for development.")
    database_url = "sqlite:///chat.db"

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Initialize Socket.IO with proper configuration
socketio = SocketIO(
    app, 
    cors_allowed_origins="*",
    manage_session=False,  # We'll manage sessions via Flask
    ping_timeout=60,
    ping_interval=25,
    async_mode='eventlet',  # Explicitly use eventlet
    logger=True,
    engineio_logger=True
)

# Get the hashed password from environment variable or use default
# The password should be stored as a hash in the environment variable
HASHED_PASSWORD = os.environ.get('HASHED_PASSWORD')
DEFAULT_PASSWORD = "password123"  # This is just for demonstration

# If no hashed password is provided, hash the default password
if not HASHED_PASSWORD:
    HASHED_PASSWORD = bcrypt.hashpw(DEFAULT_PASSWORD.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    logger.warning("Using default password! This is insecure. Set HASHED_PASSWORD in environment variables.")

logger.info("Starting application with configuration:")
logger.info(f"GOOGLE_CLOUD = {os.environ.get('GOOGLE_CLOUD', False)}")
logger.info(f"PORT = {os.environ.get('PORT', '8080')}")
logger.info(f"SECRET_KEY set = {'Yes' if os.environ.get('SECRET_KEY') else 'No'}")
logger.info(f"HASHED_PASSWORD set = {'Yes' if os.environ.get('HASHED_PASSWORD') else 'No'}")
logger.info(f"DATABASE_URL = {database_url}")
logger.info(f"OPENAI_API_KEY set = {'Yes' if os.environ.get('OPENAI_API_KEY') else 'No'}")

# Make sure tables exist
with app.app_context():
    try:
        db.create_all()
        logger.info("Database tables created if they didn't exist")
    except Exception as e:
        logger.error(f"Error creating database tables: {e}")

# Define canned responses for when the API fails
FALLBACK_RESPONSES = [
    "I'm here to help! What can I assist you with today?",
    "Hello! How can I make your day better?",
    "Greetings! I'm WladBot, your friendly assistant.",
    "Hello there! I'm ready to chat and help out.",
    "Hi! I'm currently operating in offline mode, but I'll do my best to assist you.",
    "Thanks for your message! How can I help you today?",
    "I'm WladBot, your virtual assistant. What would you like to know?",
    "Hello! I'm here to provide information and assistance.",
    "Greetings! How may I be of service to you today?",
    "Hello! I'm in offline mode right now, but I'll try to help with simple queries."
]

def get_fallback_response(user_message):
    """Get a fallback response when the API call fails"""
    # Check for greetings
    lower_msg = user_message.lower()
    if any(greeting in lower_msg for greeting in ['hello', 'hi', 'hey', 'greetings']):
        return random.choice([
            "Hello there! Nice to meet you.",
            "Hi! How can I help you today?",
            "Hey! I'm WladBot. What can I do for you?",
            "Greetings! How may I assist you?"
        ])
    
    # Check for questions about capabilities
    if any(phrase in lower_msg for phrase in ['what can you do', 'help me with', 'your capabilities']):
        return "I can help with information, answer questions, or just chat! Though I'm running in offline mode right now, so my capabilities are limited."
    
    # Check for thanks/gratitude
    if any(phrase in lower_msg for phrase in ['thank', 'thanks', 'appreciate']):
        return random.choice([
            "You're welcome! Happy to help.",
            "Anytime! Let me know if you need anything else.",
            "Glad I could assist! Is there anything else you'd like to know?"
        ])
    
    # Default response
    return random.choice(FALLBACK_RESPONSES)

def get_ai_response(user_message):
    """Get response from OpenAI API using direct HTTP requests instead of the OpenAI SDK"""
    try:
        api_key = os.environ.get('OPENAI_API_KEY')
        if not api_key:
            logger.warning("OPENAI_API_KEY not set! Using fallback responses.")
            return get_fallback_response(user_message)
        
        # Use requests library instead of OpenAI SDK
        import requests
        import json
        
        logger.info("Preparing to send request to OpenAI API...")
        
        # OpenAI API endpoint
        url = "https://api.openai.com/v1/chat/completions"
        
        # Request headers
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        
        # Request body
        data = {
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant named WladBot."},
                {"role": "user", "content": user_message}
            ],
            "max_tokens": 500
        }
        
        logger.info("Sending request to OpenAI API...")
        
        # Make the API request with a shorter timeout
        response = requests.post(
            url, 
            headers=headers, 
            json=data, 
            timeout=10  # Reduced timeout from 30 to 10 seconds
        )
        
        logger.info(f"Received response from OpenAI API: Status {response.status_code}")
        
        # Check if the request was successful
        if response.status_code == 200:
            # Parse the response
            response_data = response.json()
            # Extract the message content
            ai_response = response_data["choices"][0]["message"]["content"].strip()
            logger.info(f"Successful response from OpenAI API: {ai_response[:50]}...")
            return ai_response
        else:
            # Handle API error
            error_message = f"API Error: {response.status_code} - {response.text}"
            logger.error(error_message)
            logger.info("Using fallback response due to API error.")
            return get_fallback_response(user_message)
            
    except requests.exceptions.Timeout:
        error_message = "Request to OpenAI API timed out"
        logger.error(error_message)
        logger.info("Using fallback response due to timeout.")
        return get_fallback_response(user_message)
        
    except requests.exceptions.ConnectionError as e:
        error_message = f"Connection error when connecting to OpenAI API: {str(e)}"
        logger.error(error_message)
        logger.info("Using fallback response due to connection error.")
        return get_fallback_response(user_message)
            
    except Exception as e:
        logger.error(f"Error getting AI response: {e}")
        logger.info("Using fallback response due to exception.")
        return get_fallback_response(user_message)

@app.route('/')
def login():
    logger.debug(f"Login route accessed - IP: {request.remote_addr}, User-Agent: {request.headers.get('User-Agent')}")
    if 'authenticated' in session:
        logger.debug("User already authenticated, redirecting to index")
        return redirect(url_for('index'))
    logger.debug("Rendering login template")
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    logger.debug(f"Login attempt - IP: {request.remote_addr}")
    password = request.form.get('password')
    
    # Check if the provided password matches the stored hash
    if bcrypt.checkpw(password.encode('utf-8'), HASHED_PASSWORD.encode('utf-8')):
        logger.info(f"Successful login from {request.remote_addr}")
        session['authenticated'] = True
        session['username'] = 'User' + request.remote_addr.replace('.', '')  # Simple username generation
        return redirect(url_for('index'))
    
    logger.warning(f"Failed login attempt from {request.remote_addr}")
    return render_template('login.html', error="Invalid password")

@app.route('/index')
def index():
    logger.debug(f"Index route accessed - IP: {request.remote_addr}")
    if 'authenticated' not in session:
        logger.debug("User not authenticated, redirecting to login")
        return redirect(url_for('login'))
    logger.debug("Rendering index template")
    return render_template('index.html')

@app.route('/chat')
def chat():
    if 'authenticated' not in session:
        logger.debug("User not authenticated, redirecting to login")
        return redirect(url_for('login'))
    username = session.get('username', 'You')
    logger.debug(f"Chat route accessed by {username}")
    
    # Get recent messages from database
    with app.app_context():
        recent_messages = [msg.to_dict() for msg in Message.get_recent_messages()]
    
    return render_template('chat.html', username=username, messages=recent_messages)

# Socket.IO event handlers
@socketio.on('connect')
def handle_connect():
    logger.debug(f"Client connected: {request.sid}")
    
    # Get session from cookie for Socket.IO
    if 'authenticated' not in session:
        logger.warning(f"Unauthenticated connection attempt: {request.sid}")
        return False
    
    username = session.get('username', 'You')
    logger.info(f"User {username} connected to socket: {request.sid}")
    
    # Join a room with the same name as the session ID
    join_room(request.sid)
    
    # Send existing messages to the client
    with app.app_context():
        messages = [msg.to_dict() for msg in Message.get_recent_messages()]
    
    emit('message_history', messages)

@socketio.on('disconnect')
def handle_disconnect():
    if 'username' in session:
        logger.debug(f"Client {session['username']} disconnected: {request.sid}")
    else:
        logger.debug(f"Client disconnected: {request.sid}")

@socketio.on('send_message')
def handle_message(data):
    if 'authenticated' not in session:
        logger.warning(f"Unauthenticated message attempt: {request.sid}")
        return
    
    username = session.get('username', 'You')
    message = data.get('message', '').strip()
    
    if message:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        msg_data = {
            'username': username,
            'message': message,
            'timestamp': timestamp
        }
        
        # Save user message to database
        try:
            with app.app_context():
                new_message = Message(content=message, username=username)
                db.session.add(new_message)
                db.session.commit()
                # Use the actual database ID and timestamp
                msg_data = new_message.to_dict()
                logger.debug(f"Message saved to database with ID: {new_message.id}")
        except Exception as e:
            logger.error(f"Error saving message to database: {e}")
        
        logger.debug(f"New message from {username}: {message}")
        emit('new_message', msg_data, broadcast=True)
        
        # Get AI response
        ai_response = get_ai_response(message)
        if ai_response:
            # Save AI message to database with "WladBot" username
            try:
                with app.app_context():
                    ai_message = Message(content=ai_response, username="WladBot")
                    db.session.add(ai_message)
                    db.session.commit()
                    # Use the actual database ID and timestamp
                    ai_msg_data = ai_message.to_dict()
                    logger.debug(f"AI response saved to database with ID: {ai_message.id}")
                    
                    # Emit AI response to all clients
                    emit('new_message', ai_msg_data, broadcast=True)
            except Exception as e:
                logger.error(f"Error saving AI response to database: {e}")

if __name__ == '__main__':
    # Check if running on Google Cloud or locally
    is_cloud = os.environ.get('GOOGLE_CLOUD', False)
    
    logger.info(f"Running in {'Google Cloud' if is_cloud else 'local'} mode")
    
    if is_cloud:
        # Production settings for Google Cloud
        port = int(os.environ.get('PORT', 8080))
        logger.info(f"Starting server on port {port}")
        socketio.run(app, host='0.0.0.0', port=port, allow_unsafe_werkzeug=True)
    else:
        # Development settings for local machine
        logger.info("Starting server with SSL on port 8443")
        socketio.run(
            app,
            debug=True,
            host='0.0.0.0',
            port=8443,
            ssl_context=('certs/cert.pem', 'certs/key.pem'),
            allow_unsafe_werkzeug=True
        ) 