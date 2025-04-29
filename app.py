from flask import Flask, render_template, request, redirect, url_for, session
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session management

# In a real application, you would store this securely and use proper password hashing
PASSWORD = "password123"  # This is just for demonstration

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
    # Run with SSL context
    app.run(
        debug=True,
        ssl_context=('certs/cert.pem', 'certs/key.pem'),
        host='0.0.0.0',
        port=8443
    ) 