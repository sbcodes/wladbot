from flask import Flask, render_template, request, redirect, url_for, session
import os
import socket
import logging
import sys

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

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))  # Get from env var or generate

# In a real application, you would store this securely and use proper password hashing
PASSWORD = os.environ.get('APP_PASSWORD', "password123")  # Get from env var or use default

logger.info("Starting application with configuration:")
logger.info(f"GOOGLE_CLOUD = {os.environ.get('GOOGLE_CLOUD', False)}")
logger.info(f"PORT = {os.environ.get('PORT', '8080')}")
logger.info(f"SECRET_KEY set = {'Yes' if os.environ.get('SECRET_KEY') else 'No'}")
logger.info(f"APP_PASSWORD set = {'Yes' if os.environ.get('APP_PASSWORD') else 'No'}")

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
    if password == PASSWORD:
        logger.info(f"Successful login from {request.remote_addr}")
        session['authenticated'] = True
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

if __name__ == '__main__':
    # Check if running on Google Cloud or locally
    is_cloud = os.environ.get('GOOGLE_CLOUD', False)
    
    logger.info(f"Running in {'Google Cloud' if is_cloud else 'local'} mode")
    
    if is_cloud:
        # Production settings for Google Cloud
        port = int(os.environ.get('PORT', 8080))
        logger.info(f"Starting server on port {port}")
        app.run(host='0.0.0.0', port=port)
    else:
        # Development settings for local machine
        logger.info("Starting server with SSL on port 8443")
        app.run(
            debug=True,
            ssl_context=('certs/cert.pem', 'certs/key.pem'),
            host='0.0.0.0',
            port=8443
        ) 