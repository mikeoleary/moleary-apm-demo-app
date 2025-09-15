#!/usr/bin/env python3
"""
SOAP Authentication Demo Application
A basic Flask app with SOAP-based authentication for Ubuntu
"""

from flask import Flask, request, session, redirect, url_for, render_template_string
from spyne import Application, rpc, ServiceBase, Unicode, Boolean, Fault
from spyne.protocol.soap import Soap11
from spyne.server.wsgi import WsgiApplication
import hashlib
import secrets
from datetime import datetime, timedelta
import threading
import time

# In-memory user database (username -> {password_hash, email})
USERS_DB = {
    'admin': {
        'password_hash': hashlib.sha256('password123'.encode()).hexdigest(),
        'email': 'admin@example.com'
    },
    'user1': {
        'password_hash': hashlib.sha256('mypassword'.encode()).hexdigest(),
        'email': 'user1@example.com'
    },
    'demo': {
        'password_hash': hashlib.sha256('demo123'.encode()).hexdigest(),
        'email': 'demo@example.com'
    },
}

# Session storage (token -> user_info)
ACTIVE_SESSIONS = {}
SESSION_TIMEOUT = 3600  # 1 hour

class AuthenticationService(ServiceBase):
    """SOAP Web Service for Authentication"""
    
    @rpc(Unicode, Unicode, _returns=Unicode)
    def authenticate(ctx, username, password):
        """
        Authenticate user via SOAP
        Returns: session_token on success, raises fault on failure
        """
        # Check if user exists and password is correct
        if username not in USERS_DB:
            raise Fault('Client', 'Invalid username or password')
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if USERS_DB[username] != password_hash:
            raise Fault('Client', 'Invalid username or password')
        
        # Generate session token
        session_token = secrets.token_urlsafe(32)
        
        # Store session
        ACTIVE_SESSIONS[session_token] = {
            'username': username,
            'created_at': datetime.now(),
            'last_accessed': datetime.now()
        }
        
        return session_token
    
    @rpc(Unicode, _returns=Boolean)
    def validate_session(ctx, session_token):
        """
        Validate session token via SOAP
        Returns: True if valid, False if invalid/expired
        """
        if session_token not in ACTIVE_SESSIONS:
            return False
        
        session = ACTIVE_SESSIONS[session_token]
        
        # Check if session expired
        if datetime.now() - session['last_accessed'] > timedelta(seconds=SESSION_TIMEOUT):
            del ACTIVE_SESSIONS[session_token]
            return False
        
        # Update last accessed time
        session['last_accessed'] = datetime.now()
        return True
    
    @rpc(Unicode, _returns=Unicode)
    def get_user(ctx, session_token):
        """
        Get username from session token
        Returns: username if valid session, raises fault if invalid
        """
        if session_token not in ACTIVE_SESSIONS:
            raise Fault('Client', 'Invalid or expired session')
        
        session = ACTIVE_SESSIONS[session_token]
        
        # Check if session expired
        if datetime.now() - session['last_accessed'] > timedelta(seconds=SESSION_TIMEOUT):
            del ACTIVE_SESSIONS[session_token]
            raise Fault('Client', 'Session expired')
        
        # Update last accessed time
        session['last_accessed'] = datetime.now()
        return session['username']
    
    @rpc(Unicode, _returns=Boolean)
    def logout(ctx, session_token):
        """
        Logout and invalidate session
        Returns: True if successful
        """
        if session_token in ACTIVE_SESSIONS:
            del ACTIVE_SESSIONS[session_token]
        return True

# Create SOAP application
soap_app = Application([AuthenticationService],
                      tns='http://soap.auth.demo',
                      in_protocol=Soap11(validator='lxml'),
                      out_protocol=Soap11())

# Create WSGI application for SOAP
wsgi_soap_app = WsgiApplication(soap_app)

# Create Flask application
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# HTML Templates
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SOAP Auth Demo - Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; }
        .container { max-width: 500px; margin: 0 auto; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        input[type="text"], input[type="password"] { 
            width: 100%; padding: 8px; margin-bottom: 10px; 
        }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        .error { color: red; margin-bottom: 15px; }
        .info { background: #e7f3ff; padding: 15px; margin-bottom: 20px; border-left: 4px solid #007bff; }
    </style>
</head>
<body>
    <div class="container">
        <h1>SOAP Authentication Demo</h1>
        
        <div class="info">
            <h3>Available Test Users:</h3>
            <ul>
                <li><strong>admin</strong> / password123</li>
                <li><strong>user1</strong> / mypassword</li>
                <li><strong>demo</strong> / demo123</li>
            </ul>
        </div>
        
        {% if error %}
            <div class="error">{{ error }}</div>
        {% endif %}
        
        <form method="post">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">Login via SOAP</button>
        </form>
        
        <h3>SOAP Endpoint Information:</h3>
        <p><strong>WSDL URL:</strong> <a href="/soap?wsdl" target="_blank">http://localhost:5000/soap?wsdl</a></p>
        <p><strong>Service URL:</strong> http://localhost:5000/soap</p>
    </div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SOAP Auth Demo - Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; }
        .container { max-width: 800px; margin: 0 auto; }
        .user-info { background: #d4edda; padding: 15px; margin-bottom: 20px; border: 1px solid #c3e6cb; }
        button { background: #dc3545; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        .session-info { background: #f8f9fa; padding: 15px; margin-bottom: 20px; border: 1px solid #dee2e6; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to the Protected Dashboard</h1>
        
        <div class="user-info">
            <h3>Authenticated User</h3>
            <p><strong>Username:</strong> {{ username }}</p>
            <p><strong>Login Time:</strong> {{ login_time }}</p>
        </div>
        
        <div class="session-info">
            <h3>Session Information</h3>
            <p><strong>Session Token:</strong> {{ session_token[:20] }}...</p>
            <p><strong>Last Accessed:</strong> {{ last_accessed }}</p>
        </div>
        
        <p>This page is only accessible after SOAP authentication!</p>
        
        <form method="post" action="{{ url_for('logout') }}">
            <button type="submit">Logout</button>
        </form>
    </div>
</body>
</html>
"""

# Helper function to make SOAP calls
def soap_authenticate(username, password):
    """Make SOAP call to authenticate user"""
    from lxml import etree
    
    soap_body = f"""<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" 
                   xmlns:tns="http://soap.auth.demo">
        <soap:Body>
            <tns:authenticate>
                <tns:username>{username}</tns:username>
                <tns:password>{password}</tns:password>
            </tns:authenticate>
        </soap:Body>
    </soap:Envelope>"""
    
    # Simulate SOAP call by directly calling the service
    try:
        service = AuthenticationService()
        return service.authenticate(None, username, password)
    except Exception as e:
        return None

def soap_get_user(session_token):
    """Make SOAP call to get user from session"""
    try:
        service = AuthenticationService()
        return service.get_user(None, session_token)
    except Exception as e:
        return None

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Authenticate via SOAP
        session_token = soap_authenticate(username, password)
        
        if session_token:
            session['token'] = session_token
            return redirect(url_for('dashboard'))
        else:
            return render_template_string(LOGIN_TEMPLATE, error="Invalid credentials")
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/dashboard')
def dashboard():
    session_token = session.get('token')
    if not session_token:
        return redirect(url_for('login'))
    
    # Validate session via SOAP
    username = soap_get_user(session_token)
    if not username:
        session.pop('token', None)
        return redirect(url_for('login'))
    
    # Get session info
    session_info = ACTIVE_SESSIONS.get(session_token, {})
    
    return render_template_string(DASHBOARD_TEMPLATE,
                                username=username,
                                session_token=session_token,
                                login_time=session_info.get('created_at', 'Unknown'),
                                last_accessed=session_info.get('last_accessed', 'Unknown'))

@app.route('/logout', methods=['POST'])
def logout():
    session_token = session.get('token')
    if session_token:
        # Logout via SOAP
        service = AuthenticationService()
        service.logout(None, session_token)
        session.pop('token', None)
    
    return redirect(url_for('login'))

@app.route('/soap', methods=['GET', 'POST'])
def soap_service():
    """Handle SOAP requests"""
    if request.method == 'GET' and 'wsdl' in request.args:
        # Return WSDL
        from spyne.interface.wsdl import Wsdl11
        wsdl = Wsdl11(soap_app)
        wsdl.build_interface_document('http://localhost:5000/soap')
        return wsdl.get_interface_document(), 200, {'Content-Type': 'text/xml'}
    
    # Handle SOAP requests
    return wsgi_soap_app(request.environ, lambda status, headers: None)

def cleanup_expired_sessions():
    """Background task to clean up expired sessions"""
    while True:
        current_time = datetime.now()
        expired_tokens = []
        
        for token, session_info in ACTIVE_SESSIONS.items():
            if current_time - session_info['last_accessed'] > timedelta(seconds=SESSION_TIMEOUT):
                expired_tokens.append(token)
        
        for token in expired_tokens:
            del ACTIVE_SESSIONS[token]
        
        time.sleep(300)  # Check every 5 minutes

if __name__ == '__main__':
    print("SOAP Authentication Demo Application")
    print("=" * 40)
    print("Available users:")
    for username, user_data in USERS_DB.items():
        print(f"  - {username} ({user_data['email']})")
    print()
    print("API Endpoints:")
    print("  - POST /api/validate-password (JSON: {username, password})")
    print("  - GET /api/get-email?username=admin")
    print("  - POST /api/get-email (JSON: {username})")
    print("  - GET /logout (separate logout page)")
    print()
    print("Starting server...")
    print("Web Interface: http://localhost:5000")
    print("SOAP Endpoint: http://localhost:5000/soap")
    print("WSDL: http://localhost:5000/soap?wsdl")
    print()
    
    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_expired_sessions, daemon=True)
    cleanup_thread.start()
    
    # Start Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)

    # I generated this app using Claude Code. Feel free to copy, modify, and use it as you like.