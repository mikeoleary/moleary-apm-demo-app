#!/usr/bin/env python3
"""
SOAP Authentication Demo Application
A basic Flask app with SOAP-based authentication for Ubuntu
"""

from flask import Flask, request, session, redirect, url_for, render_template_string, jsonify
from spyne import Application, rpc, ServiceBase, Unicode, Boolean, Fault
from spyne.protocol.soap import Soap11
from spyne.server.wsgi import WsgiApplication
import hashlib
import secrets
from datetime import datetime, timedelta
import threading
import time
import logging
import logging.handlers
import os

# Configure logging
def setup_logging():
    """Setup file logging with rotation"""
    # Create logs directory if it doesn't exist
    log_dir = '/var/log/soap-auth-demo'
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, mode=0o755)
        except PermissionError:
            # Fallback to current directory if /var/log is not writable
            log_dir = './logs'
            os.makedirs(log_dir, exist_ok=True)
    
    # Main application log
    app_log_file = os.path.join(log_dir, 'soap_auth_demo.log')
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    # Remove default handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # File handler with rotation (10MB files, keep 5 backups)
    file_handler = logging.handlers.RotatingFileHandler(
        app_log_file, 
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
    
    # Console handler for immediate feedback
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    root_logger.addHandler(console_handler)
    
    # Access log (separate file)
    access_log_file = os.path.join(log_dir, 'access.log')
    access_logger = logging.getLogger('access')
    access_logger.setLevel(logging.INFO)
    access_logger.propagate = False  # Don't propagate to root logger
    
    access_handler = logging.handlers.RotatingFileHandler(
        access_log_file,
        maxBytes=10*1024*1024,
        backupCount=5
    )
    access_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(message)s'
    ))
    access_logger.addHandler(access_handler)
    
    logging.info(f"Logging initialized. Log files in: {log_dir}")
    return log_dir

# Initialize logging
LOG_DIR = setup_logging()
logger = logging.getLogger(__name__)
access_logger = logging.getLogger('access')

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
    'michaeloleary': {
        'password_hash': hashlib.sha256('TooHotSummer2025'.encode()).hexdigest(),
        'email': 'user@example.com'
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
        client_ip = getattr(ctx, 'transport', {}).get('remote_addr', 'unknown')
        logger.info(f"SOAP authentication attempt for user '{username}' from IP {client_ip}")
        
        # Check if user exists and password is correct
        if username not in USERS_DB:
            logger.warning(f"Authentication failed: unknown user '{username}' from IP {client_ip}")
            raise Fault('Client', 'Invalid username or password')
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if USERS_DB[username]['password_hash'] != password_hash:
            logger.warning(f"Authentication failed: invalid password for user '{username}' from IP {client_ip}")
            raise Fault('Client', 'Invalid username or password')
        
        # Generate session token
        session_token = secrets.token_urlsafe(32)
        
        # Store session
        ACTIVE_SESSIONS[session_token] = {
            'username': username,
            'email': USERS_DB[username]['email'],
            'created_at': datetime.now(),
            'last_accessed': datetime.now(),
            'client_ip': client_ip
        }
        
        logger.info(f"User '{username}' authenticated successfully via SOAP from IP {client_ip}, session token: {session_token[:16]}...")
        return session_token
    
    @rpc(Unicode, _returns=Boolean)
    def validate_session(ctx, session_token):
        """
        Validate session token via SOAP
        Returns: True if valid, False if invalid/expired
        """
        logger.debug(f"SOAP session validation for token: {session_token[:16]}...")
        
        if session_token not in ACTIVE_SESSIONS:
            logger.warning(f"Session validation failed: token not found {session_token[:16]}...")
            return False
        
        session = ACTIVE_SESSIONS[session_token]
        
        # Check if session expired
        if datetime.now() - session['last_accessed'] > timedelta(seconds=SESSION_TIMEOUT):
            logger.info(f"Session expired for user '{session['username']}', token: {session_token[:16]}...")
            del ACTIVE_SESSIONS[session_token]
            return False
        
        # Update last accessed time
        session['last_accessed'] = datetime.now()
        logger.debug(f"Session validated for user '{session['username']}'")
        return True
    
    @rpc(Unicode, _returns=Unicode)
    def get_user(ctx, session_token):
        """
        Get username from session token
        Returns: username if valid session, raises fault if invalid
        """
        logger.debug(f"SOAP get_user for token: {session_token[:16]}...")
        
        if session_token not in ACTIVE_SESSIONS:
            logger.warning(f"get_user failed: invalid session token {session_token[:16]}...")
            raise Fault('Client', 'Invalid or expired session')
        
        session = ACTIVE_SESSIONS[session_token]
        
        # Check if session expired
        if datetime.now() - session['last_accessed'] > timedelta(seconds=SESSION_TIMEOUT):
            logger.info(f"get_user failed: session expired for user '{session['username']}'")
            del ACTIVE_SESSIONS[session_token]
            raise Fault('Client', 'Session expired')
        
        # Update last accessed time
        session['last_accessed'] = datetime.now()
        username = session['username']
        logger.debug(f"get_user successful for user '{username}'")
        return username
    
    @rpc(Unicode, Unicode, _returns=Unicode)
    def validate_password(ctx, username, password):
        """
        Validate user password and return email if correct
        Returns: email address on success, raises fault on failure
        """
        client_ip = getattr(ctx, 'transport', {}).get('remote_addr', 'unknown')
        logger.info(f"SOAP password validation for user '{username}' from IP {client_ip}")
        
        # Check if user exists
        if username not in USERS_DB:
            logger.warning(f"Password validation failed: unknown user '{username}' from IP {client_ip}")
            raise Fault('Client', 'Invalid username or password')
        
        # Check password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if USERS_DB[username]['password_hash'] != password_hash:
            logger.warning(f"Password validation failed: invalid password for user '{username}' from IP {client_ip}")
            raise Fault('Client', 'Invalid username or password')
        
        # Return email address
        email = USERS_DB[username]['email']
        logger.info(f"Password validated successfully for user '{username}' from IP {client_ip}")
        return email
    
    @rpc(Unicode, _returns=Boolean)
    def logout(ctx, session_token):
        """
        Logout and invalidate session
        Returns: True if successful
        """
        logger.info(f"SOAP logout for token: {session_token[:16]}...")
        
        if session_token in ACTIVE_SESSIONS:
            username = ACTIVE_SESSIONS[session_token]['username']
            logger.info(f"User '{username}' logged out via SOAP, token: {session_token[:16]}...")
            del ACTIVE_SESSIONS[session_token]
        else:
            logger.warning(f"Logout attempt for non-existent session: {session_token[:16]}...")
        
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

# Flask request logging middleware
@app.before_request
def log_request():
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    access_logger.info(f"{client_ip} - {request.method} {request.path} - User-Agent: {request.headers.get('User-Agent', 'Unknown')}")

@app.after_request
def log_response(response):
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    access_logger.info(f"{client_ip} - {request.method} {request.path} - Status: {response.status_code}")
    return response

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
                <li><strong>admin</strong> / password123 (admin@example.com)</li>
                <li><strong>user1</strong> / mypassword (user1@example.com)</li>
                <li><strong>demo</strong> / demo123 (demo@example.com)</li>
                <li><strong>michaeloleary</strong> / TooHotSummer2025 (user@example.com)</li>
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

LOGOUT_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SOAP Auth Demo - Logout</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; }
        .container { max-width: 500px; margin: 0 auto; text-align: center; }
        .logout-success { background: #d1ecf1; padding: 20px; margin-bottom: 20px; border: 1px solid #bee5eb; border-radius: 4px; }
        .actions { margin-top: 30px; }
        button, .btn { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; text-decoration: none; display: inline-block; border-radius: 4px; }
        button:hover, .btn:hover { background: #0056b3; }
        h1 { color: #333; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Logout Successful</h1>
        
        <div class="logout-success">
            <h3>✅ You have been successfully logged out</h3>
            <p>Your session has been invalidated and you have been securely logged out of the system.</p>
        </div>
        
        <div class="actions">
            <a href="{{ url_for('login') }}" class="btn">Login Again</a>
        </div>
        
        <div style="margin-top: 30px; font-size: 12px; color: #666;">
            <p>Session cleared at: {{ logout_time }}</p>
        </div>
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
            <p><strong>Email:</strong> {{ email }}</p>
            <p><strong>Login Time:</strong> {{ login_time }}</p>
        </div>
        
        <div class="session-info">
            <h3>Session Information</h3>
            <p><strong>Session Token:</strong> {{ session_token[:20] }}...</p>
            <p><strong>Last Accessed:</strong> {{ last_accessed }}</p>
        </div>
        
        <p>This page is only accessible after SOAP authentication!</p>
        
        <form method="post" action="{{ url_for('logout_page') }}">
            <button type="submit">Logout</button>
        </form>
    </div>
</body>
</html>
"""

# Helper function to make SOAP calls
def soap_authenticate(username, password):
    """Make SOAP call to authenticate user"""
    logger.debug(f"Internal SOAP authentication call for user: {username}")
    try:
        service = AuthenticationService()
        return service.authenticate(None, username, password)
    except Exception as e:
        logger.error(f"SOAP authentication error for user '{username}': {str(e)}")
        return None

def soap_get_user(session_token):
    """Make SOAP call to get user from session"""
    logger.debug(f"Internal SOAP get_user call for token: {session_token[:16]}...")
    try:
        service = AuthenticationService()
        return service.get_user(None, session_token)
    except Exception as e:
        logger.error(f"SOAP get_user error for token {session_token[:16]}...: {str(e)}")
        return None

@app.route('/', methods=['GET', 'POST'])
def login():
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    
    if request.method == 'POST':
        username = request.form['username']
        logger.info(f"Web login attempt for user '{username}' from IP {client_ip}")
        
        password = request.form['password']
        
        # Authenticate via SOAP
        session_token = soap_authenticate(username, password)
        
        if session_token:
            session['token'] = session_token
            logger.info(f"Web login successful for user '{username}' from IP {client_ip}")
            return redirect(url_for('dashboard'))
        else:
            logger.warning(f"Web login failed for user '{username}' from IP {client_ip}")
            return render_template_string(LOGIN_TEMPLATE, error="Invalid credentials"), 401
    
    logger.debug(f"Serving login page to IP {client_ip}")
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/dashboard')
def dashboard():
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    session_token = session.get('token')
    
    if not session_token:
        logger.info(f"Dashboard access denied: no session token from IP {client_ip}")
        return redirect(url_for('login'))
    
    # Validate session via SOAP
    username = soap_get_user(session_token)
    if not username:
        logger.warning(f"Dashboard access denied: invalid session token from IP {client_ip}")
        session.pop('token', None)
        return redirect(url_for('login'))
    
    # Get session info
    session_info = ACTIVE_SESSIONS.get(session_token, {})
    logger.info(f"Dashboard accessed by user '{username}' from IP {client_ip}")
    
    return render_template_string(DASHBOARD_TEMPLATE,
                                username=username,
                                email=session_info.get('email', 'Unknown'),
                                session_token=session_token,
                                login_time=session_info.get('created_at', 'Unknown'),
                                last_accessed=session_info.get('last_accessed', 'Unknown'))

@app.route('/logout', methods=['POST', 'GET'])
def logout_page():
    """Separate logout page"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    session_token = session.get('token')
    
    if session_token:
        username = ACTIVE_SESSIONS.get(session_token, {}).get('username', 'unknown')
        logger.info(f"Web logout for user '{username}' from IP {client_ip}")
        
        # Logout via SOAP
        service = AuthenticationService()
        service.logout(None, session_token)
        session.pop('token', None)
    else:
        logger.info(f"Logout attempt with no session from IP {client_ip}")
    
    logout_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return render_template_string(LOGOUT_TEMPLATE, logout_time=logout_time)

@app.route('/api/validate-password', methods=['POST'])
def api_validate_password():
    """API endpoint to validate password and return email"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    logger.info(f"API validate-password request from IP {client_ip}")
    
    try:
        # Get JSON data from request
        data = request.get_json()
        
        if not data or 'username' not in data or 'password' not in data:
            logger.warning(f"API validate-password: missing credentials from IP {client_ip}")
            return jsonify({'error': 'Username and password required'}), 400
        
        username = data['username']
        password = data['password']
        logger.info(f"API validate-password for user '{username}' from IP {client_ip}")
        
        # Validate via SOAP service
        service = AuthenticationService()
        email = service.validate_password(None, username, password)
        
        logger.info(f"API validate-password successful for user '{username}' from IP {client_ip}")
        return jsonify({
            'success': True,
            'username': username,
            'email': email,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"API validate-password error from IP {client_ip}: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Invalid username or password'
        }), 401

@app.route('/api/get-email', methods=['GET', 'POST'])
def api_get_email():
    """API endpoint to get email address by username"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    logger.info(f"API get-email request from IP {client_ip}")
    
    try:
        # Handle both GET and POST requests
        if request.method == 'GET':
            username = request.args.get('username')
        else:  # POST
            data = request.get_json()
            if not data or 'username' not in data:
                logger.warning(f"API get-email: missing username from IP {client_ip}")
                return jsonify({'error': 'Username required'}), 400
            username = data['username']
        
        if not username:
            logger.warning(f"API get-email: no username provided from IP {client_ip}")
            return jsonify({'error': 'Username required'}), 400
        
        logger.info(f"API get-email for user '{username}' from IP {client_ip}")
        
        # Check if user exists
        if username not in USERS_DB:
            logger.warning(f"API get-email: user '{username}' not found from IP {client_ip}")
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        # Return email address
        email = USERS_DB[username]['email']
        logger.info(f"API get-email successful for user '{username}' from IP {client_ip}")
        return jsonify({
            'success': True,
            'username': username,
            'email': email,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"API get-email error from IP {client_ip}: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

@app.route('/soap', methods=['GET', 'POST'])
def soap_service():
    """Handle SOAP requests"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    
    if request.method == 'GET' and 'wsdl' in request.args:
        logger.info(f"WSDL request from IP {client_ip}")
        # Return WSDL
        from spyne.interface.wsdl import Wsdl11
        wsdl = Wsdl11(soap_app)
        wsdl.build_interface_document('http://localhost:5000/soap')
        return wsdl.get_interface_document(), 200, {'Content-Type': 'text/xml'}
    
    logger.debug(f"SOAP request from IP {client_ip}")
    # Handle SOAP requests
    return wsgi_soap_app(request.environ, lambda status, headers: None)

def cleanup_expired_sessions():
    """Background task to clean up expired sessions"""
    logger.info("Session cleanup thread started")
    
    while True:
        try:
            current_time = datetime.now()
            expired_tokens = []
            
            for token, session_info in ACTIVE_SESSIONS.items():
                if current_time - session_info['last_accessed'] > timedelta(seconds=SESSION_TIMEOUT):
                    expired_tokens.append((token, session_info['username']))
            
            if expired_tokens:
                logger.info(f"Cleaning up {len(expired_tokens)} expired sessions")
                for token, username in expired_tokens:
                    logger.info(f"Removing expired session for user '{username}', token: {token[:16]}...")
                    del ACTIVE_SESSIONS[token]
            
            # Log session statistics
            active_count = len(ACTIVE_SESSIONS)
            if active_count > 0:
                logger.debug(f"Currently {active_count} active sessions")
            
        except Exception as e:
            logger.error(f"Error in session cleanup: {str(e)}")
        
        time.sleep(300)  # Check every 5 minutes

if __name__ == '__main__':
    logger.info("SOAP Authentication Demo Application Starting")
    logger.info("=" * 50)
    
    logger.info("Available users:")
    for username, user_data in USERS_DB.items():
        logger.info(f"  - {username} ({user_data['email']})")
    
    logger.info("API Endpoints:")
    logger.info("  - POST /api/validate-password (JSON: {username, password})")
    logger.info("  - GET /api/get-email?username=admin")
    logger.info("  - POST /api/get-email (JSON: {username})")
    logger.info("  - GET /logout (separate logout page)")
    
    logger.info(f"Log files location: {LOG_DIR}")
    logger.info("  - Main log: soap_auth_demo.log")
    logger.info("  - Access log: access.log")
    
    logger.info("Starting server...")
    logger.info("Web Interface: http://localhost:5000")
    logger.info("SOAP Endpoint: http://localhost:5000/soap")
    logger.info("WSDL: http://localhost:5000/soap?wsdl")
    
    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_expired_sessions, daemon=True)
    cleanup_thread.start()
    
    # Start Flask app
    try:
        app.run(host='0.0.0.0', port=5000, debug=False)  # Changed debug=False for production
    except Exception as e:
        logger.error(f"Failed to start Flask app: {str(e)}")
        raise