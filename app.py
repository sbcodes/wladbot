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

# Message storage - in a real app, you'd use a database
messages = []

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
    return render_template('chat.html', username=username, messages=messages)

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
        messages.append(msg_data)
        
        # Keep only the last 100 messages
        while len(messages) > 100:
            messages.pop(0)
        
        logger.debug(f"New message from {username}: {message}")
        emit('new_message', msg_data, broadcast=True)

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