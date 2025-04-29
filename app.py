from flask import Flask, render_template, request, redirect, url_for, session
import os
import socket

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))  # Get from env var or generate

# In a real application, you would store this securely and use proper password hashing
PASSWORD = os.environ.get('APP_PASSWORD', "password123")  # Get from env var or use default

@app.route('/')
def login():
    if 'authenticated' in session:
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    password = request.form.get('password')
    if password == PASSWORD:
        session['authenticated'] = True
        return redirect(url_for('index'))
    return render_template('login.html', error="Invalid password")

@app.route('/index')
def index():
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

if __name__ == '__main__':
    # Check if running on Google Cloud or locally
    is_cloud = os.environ.get('GOOGLE_CLOUD', False)
    
    if is_cloud:
        # Production settings for Google Cloud
        app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
    else:
        # Development settings for local machine
        app.run(
            debug=True,
            ssl_context=('certs/cert.pem', 'certs/key.pem'),
            host='0.0.0.0',
            port=8443
        ) 