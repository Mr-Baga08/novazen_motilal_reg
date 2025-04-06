# app.py - Main Flask application (SQLite version)
from flask import Flask, request, jsonify, session, g
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import sqlite3
import re
import json  # Added missing import
from dotenv import load_dotenv
import secrets
import traceback
import functools
import logging
from logging.handlers import RotatingFileHandler

# Try to import the API - handle gracefully if not available yet
try:
    from MOFSLOPENAPI import MOFSLOPENAPI
except ImportError:
    print("Warning: MOFSLOPENAPI module not found. You'll need to install it before using the API features.")
    # Create a mock class for testing
    class MOFSLOPENAPI:
        def __init__(self, *args, **kwargs):
            self.auth_token = None
        def login(self, *args, **kwargs):
            return {"isAuthTokenVerified": "FALSE", "AuthToken": "mock_token"}
        def verifyotp(self, otp):
            return {"status": "SUCCESS", "AuthToken": "mock_verified_token"}
        def resendotp(self):
            return {"status": "SUCCESS"}
        def set_auth_token(self, token):
            self.auth_token = token

# Load environment variables
load_dotenv()

# Configure logging
log_dir = os.getenv("LOG_DIR", "logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "app.log")

# Set up rotating file handler
handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
handler.setLevel(logging.INFO)

# Set up application logger
app = Flask(__name__)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Application starting up')

# Enhanced CORS configuration with specific origins
allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3001").split(",")
CORS(app, 
     origins=allowed_origins,
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])


bcrypt = Bcrypt(app)

# Configure server-side session
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(16))
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = True # Changed to True for persistence
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_COOKIE_PATH"] = "/"
app.config["SESSION_COOKIE_DOMAIN"] = None
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Added for better cookie security
app.config["SESSION_COOKIE_SECURE"] = os.getenv("HTTPS_ENABLED", "False").lower() == "true"  # True in HTTPS environments
app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevents JavaScript access to the cookie
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=24)  # Changed to timedelta object
app.config["SESSION_FILE_DIR"] = os.path.join(os.getcwd(), 'flask_session')
app.config["SESSION_COOKIE_NAME"] = "mofsl_session"

# Create the session directory if it doesn't exist
os.makedirs(app.config["SESSION_FILE_DIR"], exist_ok=True)

Session(app)

# Configuration
BASE_URL = os.getenv("BASE_URL", "https://openapi.motilaloswal.com")
SOURCE_ID = os.getenv("SOURCE_ID", "WEB")
BROWSER_NAME = os.getenv("BROWSER_NAME", "Chrome")
BROWSER_VERSION = os.getenv("BROWSER_VERSION", "96.0.4664.110")
TOTP = os.getenv("TOTP", "FALSE")
DB_PATH = os.getenv("DB_PATH", "mofsl_data.db")

# Dictionary to store MOFSL client instances
mofsl_clients = {}

# Global error handler
@app.errorhandler(Exception)
def handle_exception(e):
    """Global exception handler"""
    traceback.print_exc()  # Print stack trace to console
    
    # In production, you might want to be less verbose for security reasons
    if app.config['ENV'] == 'production':
        return jsonify({
            'status': 'ERROR',
            'message': 'An internal server error occurred'
        }), 500
    else:
        # In development, show more details
        return jsonify({
            'status': 'ERROR',
            'message': str(e),
            'error_type': e.__class__.__name__,
            'traceback': traceback.format_exc()
        }), 500

# Function to log requests to the audit log
def log_request():
    """Log request to the audit log table"""
    try:
        client_id = session.get('client_id')
        action = f"{request.method} {request.path}"
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        # Don't log sensitive data
        details = {
            'query_params': dict(request.args),
            'content_type': request.content_type,
            'referrer': request.referrer,
            'endpoint': request.endpoint
        }
        
        # Convert details to JSON string
        details_json = json.dumps(details)
        
        # Log to database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO audit_log (client_id, action, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?)",
            (client_id, action, ip_address, user_agent, details_json)
        )
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        app.logger.error(f"Error logging request: {str(e)}")
        # Don't fail the request if logging fails

# Middleware to add auth token to request context and check token expiration
@app.before_request
def add_auth_token():
    """Add the auth token to the request context and check expiration"""
    client_id = session.get('client_id')
    
    # Check token expiration
    if 'token_expires_at' in session:
        expires_at = datetime.strptime(session['token_expires_at'], "%Y-%m-%d %H:%M:%S")
        if datetime.now() > expires_at:
            # Token has expired, clear the session
            app.logger.warning(f"Auth token expired for client {client_id}")
            session.pop('auth_token', None)
            session.pop('token_expires_at', None)
            # Don't clear client_id to allow easier re-authentication
    
    # Set up client and token in the request context
    if client_id and client_id in mofsl_clients:
        g.mofsl_client = mofsl_clients[client_id]
    
    if 'auth_token' in session:
        g.auth_token = session['auth_token']
        
        # If we have both client and token, ensure the client has the token
        if hasattr(g, 'mofsl_client') and hasattr(g.mofsl_client, 'set_auth_token'):
            g.mofsl_client.set_auth_token(session['auth_token'])
    
    # # Log request for audit purposes (excluding certain paths)
    # excluded_paths = ['/static/', '/favicon.ico']
    # if not any(request.path.startswith(path) for path in excluded_paths):
    #     log_request()

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create clients table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS clients (
        client_id TEXT PRIMARY KEY,
        api_key TEXT NOT NULL,
        userid TEXT NOT NULL,
        password TEXT,
        two_fa TEXT NOT NULL,
        vendor_info TEXT NOT NULL,
        client_code TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create ox_codes table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ox_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        client_id TEXT NOT NULL,
        userid TEXT NOT NULL,
        ox_code TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        FOREIGN KEY (client_id) REFERENCES clients (client_id)
    )
    ''')
    
    # Create audit log table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        client_id TEXT,
        action TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        details TEXT
    )
    ''')

    # Create credential_changes table for auditing
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS credential_changes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        client_id TEXT NOT NULL,
        changed_by TEXT,
        field_changed TEXT NOT NULL,
        FOREIGN KEY (client_id) REFERENCES clients (client_id)
    )
    ''')
    
    conn.commit()
    conn.close()
    
    app.logger.info("Database initialized successfully")

# Load client data from the database
def load_clients():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM clients")
    rows = cursor.fetchall()
    
    clients = {}
    for row in rows:
        clients[row['client_id']] = {
            'api_key': row['api_key'],
            'userid': row['userid'],
            'password': row['password'] or '',
            'two_fa': row['two_fa'],
            'vendor_info': row['vendor_info'],
            'client_code': row['client_code']
        }
    
    conn.close()
    print(clients)
    
    # If no clients in database, load from environment variables
    if not clients:
        # clients = {
        #     'client_1': {
        #         'api_key': os.getenv('CLIENT1_API_KEY', ''),
        #         'userid': os.getenv('CLIENT1_USERID', ''),
        #         'password': '',
        #         'two_fa': os.getenv('CLIENT1_TWO_FA', ''),
        #         'vendor_info': os.getenv('CLIENT1_VENDOR_INFO', ''),
        #         'client_code': None
        #     },
        #     'client_2': {
        #         'api_key': os.getenv('CLIENT2_API_KEY', ''),
        #         'userid': os.getenv('CLIENT2_USERID', ''),
        #         'password': '',
        #         'two_fa': os.getenv('CLIENT2_TWO_FA', ''),
        #         'vendor_info': os.getenv('CLIENT2_VENDOR_INFO', ''),
        #         'client_code': None
        #     }
        # }
        
        # Save default clients to database
        for client_id, client_data in clients.items():
            if client_data['api_key'] and client_data['userid']:
                save_client(client_id, client_data)
    
    return clients

def save_client(client_id, client_data):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Store the password as plain text without hashing
    password = client_data.get('password', '')
    
    cursor.execute(
        "INSERT OR REPLACE INTO clients (client_id, api_key, userid, password, two_fa, vendor_info, client_code) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            client_id,
            client_data['api_key'],
            client_data['userid'],
            password,  # Store as plain text
            client_data['two_fa'],
            client_data['vendor_info'],
            client_data.get('client_code')
        )
    )
    
    conn.commit()
    conn.close()
    
    return True

# Store OX code in the database
def store_ox_code(client_id, userid, auth_token):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Set token expiration (24 hours from now)
    expires_at = (datetime.now() + timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    
    # Set token in session with explicit debugging
    print(f"Before setting session: client_id={session.get('client_id')}, auth_token={'present' if 'auth_token' in session else 'missing'}")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # First, deactivate any existing active tokens for this client
    cursor.execute(
        "UPDATE ox_codes SET is_active = 0 WHERE client_id = ? AND is_active = 1",
        (client_id,)
    )
    
    # Then insert the new token
    cursor.execute(
        "INSERT INTO ox_codes (timestamp, client_id, userid, ox_code, expires_at, is_active) VALUES (?, ?, ?, ?, ?, 1)",
        (timestamp, client_id, userid, auth_token, expires_at)
    )
    
    conn.commit()
    conn.close()
    
    # Set both client_id and auth_token in session
    session['client_id'] = client_id
    session['auth_token'] = auth_token
    session['token_expires_at'] = expires_at
    
    # Force the session to be saved
    session.modified = True
    
    print(f"After setting session: client_id={session.get('client_id')}, auth_token={'present' if 'auth_token' in session else 'missing'}")
    app.logger.info(f"Stored new auth token for client {client_id}")
    
    return True

# Set auth token on MOFSL client
def set_auth_token_on_client(client_id, auth_token):
    """Set the auth token on the MOFSL client for future API calls"""
    global mofsl_clients
    
    if client_id in mofsl_clients and hasattr(mofsl_clients[client_id], 'set_auth_token'):
        mofsl_clients[client_id].set_auth_token(auth_token)
        print(f"Auth token set for client {client_id}")
        return True
    
    return False

# Initialize MOFSL API client
def get_mofsl_client(client_id):
    global mofsl_clients
    
    # Return cached client if available
    if client_id in mofsl_clients:
        return mofsl_clients[client_id]
    
    # Otherwise create a new client
    clients = load_clients()
    if client_id not in clients:
        return None
    
    credentials = clients[client_id]
    client = MOFSLOPENAPI(
        credentials['api_key'],
        BASE_URL,
        credentials['client_code'],
        SOURCE_ID,
        BROWSER_NAME,
        BROWSER_VERSION
    )
    

    print(client)
    # Cache the client
    mofsl_clients[client_id] = client
    
    # Apply auth token if available in session
    if 'auth_token' in session:
        set_auth_token_on_client(client_id, session['auth_token'])
    
    return client

# Helper function for authenticated API calls
def make_authenticated_api_call(client_id, method_name, *args, **kwargs):
    """Make an authenticated API call to the MOFSL API"""
    try:
        # Get the MOFSL client
        mofsl_client = get_mofsl_client(client_id)
        
        if not mofsl_client:
            return {"status": "ERROR", "message": "Failed to initialize API client"}, 500
        
        # Get the method to call
        method = getattr(mofsl_client, method_name, None)
        
        if not method:
            return {"status": "ERROR", "message": f"Method {method_name} not found"}, 500
        
        # Make the API call
        result = method(*args, **kwargs)
        
        # Check if the result indicates an auth issue
        if isinstance(result, dict) and result.get('message') == 'Authorization is Invalid In Header Parameter':
            # Token might have expired, clear it
            if 'auth_token' in session:
                session.pop('auth_token', None)
            
            return {"status": "ERROR", "message": "Authorization token expired. Please log in again."}, 401
        
        return result, 200
    
    except Exception as e:
        traceback.print_exc()
        return {"status": "ERROR", "message": str(e)}, 500

@app.route('/api/register', methods=['POST'])
def register():
    """Register a new client"""
    data = request.json
    if not data:
        return jsonify({
            'status': 'ERROR',
            'message': 'No JSON data received'
        }), 400
        
    client_id = data.get('client_id')
    api_key = data.get('api_key')
    userid = data.get('userid')
    password = data.get('password', '')
    two_fa = data.get('two_fa')  # This is the PAN card number
    vendor_info = data.get('vendor_info', userid)  # Default to userid if not provided
    client_code = data.get('client_code')
    
    # Note: The password will be hashed in the save_client function
    
    # Validate required fields
    if not all([client_id, api_key, userid, two_fa]):
        return jsonify({
            'status': 'ERROR',
            'message': 'Client ID, API Key, User ID, and PAN Card are required'
        }), 400
    
    # Basic PAN card validation
    pan_regex = r'^[A-Z]{5}[0-9]{4}[A-Z]{1}$'
    if not re.match(pan_regex, two_fa):
        return jsonify({
            'status': 'ERROR',
            'message': 'Invalid PAN card format. It should be in the format ABCDE1234F'
        }), 400
    
    # Load existing clients to check if client_id exists
    clients = load_clients()
    
    # Check if client already exists
    if client_id in clients:
        return jsonify({
            'status': 'ERROR',
            'message': 'Client ID already exists'
        }), 400
    
    # Ensure vendor_info is same as userid
    if not vendor_info or vendor_info != userid:
        vendor_info = userid
    
    # Add new client
    client_data = {
        'api_key': api_key,
        'userid': userid,
        'password': password,
        'two_fa': two_fa,
        'vendor_info': vendor_info,
        'client_code': client_code
    }
    
    # Save to database
    save_client(client_id, client_data)
    
    return jsonify({
        'status': 'SUCCESS',
        'message': 'Client registered successfully'
    })

@app.route('/api/login', methods=['POST'])
def login():
    """Client authentication and OTP initiation"""
    data = request.json
    print(data)
    if not data:
        return jsonify({
            'status': 'ERROR',
            'message': 'No JSON data received'
        }), 400
        
    client_id = data.get('client_id')
    password = data.get('password', '')  # Get password from request
    print(data)
    if not client_id:
        return jsonify({
            'status': 'ERROR',
            'message': 'Client ID is required'
        }), 400
    
    # Load clients
    clients = load_clients()
    print(data)
    # Check if client exists
    if client_id not in clients:
        return jsonify({
            'status': 'ERROR',
            'message': 'Client not found. Please register first.'
        }), 404
    
    credentials = clients[client_id]
    print(data)
    try:
        # Initialize MOFSL client
        mofsl_client = get_mofsl_client(client_id)
        
        if not mofsl_client:
            return jsonify({
                'status': 'ERROR',
                'message': 'Failed to initialize API client'
            }), 500
        
        # Get the stored password - it's hashed in the database
        # But we need to send the original password to the MOFSL API
        # For this login method, we'll use the password sent from the frontend
        # If no password provided in the request, use an empty string
        # password = data.get('password', '') or ''
        
        # Attempt login to get OTP
        login_response = mofsl_client.login(
            credentials['userid'],
            credentials['password']  ,
            credentials['two_fa'],
            TOTP,
            credentials['vendor_info']
        )
        print("Login response:", login_response)
        print("Is OTP needed:", login_response.get('isAuthTokenVerified') != 'TRUE')
        
        # Store client_id in session
        session['client_id'] = client_id
        
        # Store login response in session for OTP verification
        session['login_response'] = login_response
        session.modified = True
        
        # Check if OTP verification is needed
        if login_response.get('isAuthTokenVerified') == 'TRUE':
            # OTP already verified, store the OX code
            auth_token = login_response.get('AuthToken')
            if auth_token:
                # Store token in database and session
                store_ox_code(client_id, credentials['userid'], auth_token)
                
                # Set token on MOFSL client for future API calls
                set_auth_token_on_client(client_id, auth_token)
                
                print(f"Auth token stored for client {client_id}: {auth_token[:10]}...")
            
            return jsonify({
                'status': 'SUCCESS',
                'message': 'Authentication successful, OTP already verified',
                'needOTP': False,
                'client_id': client_id  # Return client_id to frontend
            })
        else:
            # OTP verification needed
            return jsonify({
                'status': 'SUCCESS',
                'message': 'OTP sent to registered mobile/email',
                'needOTP': True,
                'client_id': client_id  # Return client_id to frontend
            })
    
    except Exception as e:
        traceback.print_exc()  # Print stack trace for debugging
        return jsonify({
            'status': 'ERROR',
            'message': f'Authentication failed: {str(e)}'
        }), 500

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    """Verify OTP for client authentication"""
    try:
        data = request.json
        if not data:
            return jsonify({
                'status': 'ERROR',
                'message': 'No JSON data received'
            }), 400
            
        otp = data.get('otp')
        client_id = data.get('client_id')  # Get client_id from request
        
        if not otp:
            return jsonify({
                'status': 'ERROR',
                'message': 'OTP is required'
            }), 400
        
        # Check session - fallback to request client_id if session is empty
        if 'client_id' not in session and not client_id:
            return jsonify({
                'status': 'ERROR',
                'message': 'No active authentication session. Please authenticate again.'
            }), 401
        
        # Use client_id from session or from request
        client_id = session.get('client_id') or client_id
        
        # Update session with client_id from request if needed
        if 'client_id' not in session and client_id:
            session['client_id'] = client_id
            session.modified = True
        
        # Load configuration
        clients = load_clients()
        if client_id not in clients:
            return jsonify({
                'status': 'ERROR',
                'message': 'Invalid client ID'
            }), 404
        
        # Initialize MOFSL client
        mofsl_client = get_mofsl_client(client_id)
        
        if not mofsl_client:
            return jsonify({
                'status': 'ERROR',
                'message': 'Failed to initialize API client'
            }), 500
        
        # Verify OTP
        print(f"Verifying OTP for client {client_id}")
        otp_response = mofsl_client.verifyotp(otp)
        print("OTP verification response:", otp_response)
        
        if otp_response.get('status') == 'SUCCESS':
            # OTP verification successful, store the OX code
            credentials = clients[client_id]
            
            auth_token = otp_response.get('AuthToken')
            if auth_token:
                # Store OX code in database and session
                store_ox_code(client_id, credentials['userid'], auth_token)
                
                # Set token on MOFSL client for future API calls
                set_auth_token_on_client(client_id, auth_token)
                
                print(f"Auth token stored after OTP verification for client {client_id}: {auth_token[:10]}...")
            else:
                # If the API didn't return an auth token, we might need to use the login response token
                login_response = session.get('login_response', {})
                auth_token = login_response.get('AuthToken')
                if auth_token:
                    # Store OX code in database and session
                    store_ox_code(client_id, credentials['userid'], auth_token)
                    
                    # Set token on MOFSL client for future API calls
                    set_auth_token_on_client(client_id, auth_token)
                    
                    print(f"Using login auth token after OTP verification for client {client_id}: {auth_token[:10]}...")
            
            # Keep client_id in session but remove login response
            session.pop('login_response', None)
            
            # Force session save
            session.modified = True
            
            return jsonify({
                'status': 'SUCCESS',
                'message': 'Authentication successful! OTP verified.'
            })
        else:
            # OTP verification failed
            return jsonify({
                'status': 'ERROR',
                'message': 'Invalid OTP. Please try again.',
                'response': otp_response
            }), 400
    
    except Exception as e:
        traceback.print_exc()  # Print stack trace for debugging
        return jsonify({
            'status': 'ERROR',
            'message': f'OTP verification failed: {str(e)}'
        }), 500

@app.route('/api/resend-otp', methods=['POST'])
def resend_otp():
    """Resend OTP for client authentication"""
    try:
        data = request.json
        client_id = data.get('client_id') if data else None
        
        # Check session - fallback to request client_id if session is empty
        if 'client_id' not in session and not client_id:
            return jsonify({
                'status': 'ERROR',
                'message': 'No active authentication session. Please authenticate again.'
            }), 401
        
        # Use client_id from session or from request
        client_id = session.get('client_id') or client_id
        
        # Update session with client_id from request if needed
        if 'client_id' not in session and client_id:
            session['client_id'] = client_id
            session.modified = True
        
        # Load configuration
        clients = load_clients()
        if client_id not in clients:
            return jsonify({
                'status': 'ERROR',
                'message': 'Invalid client ID'
            }), 404
        
        # Initialize MOFSL client
        mofsl_client = get_mofsl_client(client_id)
        
        if not mofsl_client:
            return jsonify({
                'status': 'ERROR',
                'message': 'Failed to initialize API client'
            }), 500
        
        # Resend OTP
        print(f"Resending OTP for client {client_id}")
        resend_response = mofsl_client.resendotp()
        print("Resend OTP response:", resend_response)
        
        return jsonify({
            'status': 'SUCCESS',
            'message': 'OTP resent successfully to your registered mobile/email',
            'response': resend_response
        })
    
    except Exception as e:
        traceback.print_exc()  # Print stack trace for debugging
        return jsonify({
            'status': 'ERROR',
            'message': f'Failed to resend OTP: {str(e)}'
        }), 500

# Enhanced CORS configuration and security headers
@app.after_request
def after_request(response):
    # Security headers
    response.headers.add('X-Content-Type-Options', 'nosniff')
    response.headers.add('X-Frame-Options', 'DENY')
    response.headers.add('X-XSS-Protection', '1; mode=block')
    response.headers.add('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    
    # # CORS headers - these might be redundant with Flask-CORS but ensure they're set consistently
    # origin = request.headers.get('Origin')
    # if origin and origin in allowed_origins:
    #     response.headers.add('Access-Control-Allow-Origin', origin)
    #     response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    #     response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    #     response.headers.add('Access-Control-Allow-Credentials', 'true')
    
    return response

@app.route('/api/logout', methods=['POST'])
def logout():
    """Logout client and clear session"""
    # Clear the session
    session.clear()
    
    return jsonify({
        'status': 'SUCCESS',
        'message': 'Logged out successfully'
    })

# Authentication check decorator
def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        print("Login Required Check:")
        print(f"Client ID in session: {session.get('client_id')}")
        print(f"Auth Token in session: {'Present' if 'auth_token' in session else 'Missing'}")
        
        if 'client_id' not in session:
            print("Authentication failed: No client_id in session")
            return jsonify({
                'status': 'ERROR',
                'message': 'Authentication required - No client ID'
            }), 401
        
        if 'auth_token' not in session:
            print("Authentication failed: No auth_token in session")
            return jsonify({
                'status': 'ERROR',
                'message': 'Authentication required - No auth token'
            }), 401
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/ox-codes', methods=['GET'])
@login_required
def get_ox_codes():
    """Get all OX codes (protected route)"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get client_id from session
    client_id = session.get('client_id')
    
    # Only return OX codes for the authenticated client
    cursor.execute("SELECT * FROM ox_codes WHERE client_id = ? ORDER BY timestamp DESC", (client_id,))
    rows = cursor.fetchall()
    
    result = []
    for row in rows:
        result.append({
            'id': row['id'],
            'timestamp': row['timestamp'],
            'userid': row['userid'],
            # Don't send the full OX code to frontend for security
            'ox_code': row['ox_code'][:10] + '...' if row['ox_code'] else None
        })
    
    conn.close()
    
    return jsonify(result)

# Add this to app.py after the other API endpoints

@app.route('/api/client-info', methods=['GET'])
@login_required
def get_client_info():
    """Get information about the currently authenticated client"""
    print("Debugging session")
    print(session)

    # Get client_id from session
    client_id = session.get('client_id')
    print("printing client id",client_id)
    # Load client data
    clients = load_clients()
    
    # Check if client exists
    if client_id not in clients:
        return jsonify({
            'status': 'ERROR',
            'message': 'Client not found'
        }), 404
    
    # Get client data
    client_data = clients[client_id]
    
    # Return client info (excluding password for security)
    return jsonify({
        'status': 'SUCCESS',
        'client': {
            'client_id': client_id,
            'api_key': client_data['api_key'],
            'userid': client_data['userid'],
            'two_fa': client_data['two_fa'],
            'vendor_info': client_data['vendor_info'],
            'client_code': client_data.get('client_code', '')
        }
    })

# Simple route to check session state
@app.route('/api/check-session', methods=['GET'])
def check_session():
    """Check current session state"""
    return jsonify({
        'client_id': session.get('client_id'),
        'has_auth_token': 'auth_token' in session,
        'session_keys': list(session.keys())
    })

# API endpoint that demonstrates using the authenticated client
@app.route('/api/test-auth', methods=['GET'])
@login_required
def test_auth():
    """Test endpoint to verify authentication is working"""
    client_id = session['client_id']
    
    # Log this access for security monitoring
    app.logger.info(f"Auth test endpoint accessed by client {client_id}")
    
    return jsonify({
        'status': 'SUCCESS',
        'message': f'Authentication is valid for client {client_id}',
        'token_exists': True,
        'token_preview': session['auth_token'][:10] + '...' if session['auth_token'] else None
    })

# Initialize database before running the app
init_db()

# Rate limiting implementation
def get_request_count(client_id, window_seconds=60):
    """Get the number of requests made by a client in the last window_seconds"""
    if not client_id:
        return 0
        
    now = datetime.now()
    window_start = (now - timedelta(seconds=window_seconds)).strftime("%Y-%m-%d %H:%M:%S")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT COUNT(*) FROM audit_log WHERE client_id = ? AND timestamp > ?",
        (client_id, window_start)
    )
    
    count = cursor.fetchone()[0]
    conn.close()
    
    return count

# Rate limiting middleware
@app.before_request
def rate_limit():
    """Apply rate limiting to the requests"""
    # Skip for certain paths
    excluded_paths = ['/static/', '/favicon.ico']
    if any(request.path.startswith(path) for path in excluded_paths):
        return
    
    client_id = session.get('client_id')
    if not client_id:
        return
    
    # Get rate limits from environment or use defaults
    rate_limit_window = int(os.getenv('RATE_LIMIT_WINDOW', 60))  # seconds
    rate_limit_max = int(os.getenv('RATE_LIMIT_MAX', 100))  # requests per window
    
    # Get current request count
    count = get_request_count(client_id, rate_limit_window)
    
    if count > rate_limit_max:
        app.logger.warning(f"Rate limit exceeded for client {client_id}")
        return jsonify({
            'status': 'ERROR',
            'message': 'Rate limit exceeded. Please try again later.'
        }), 429

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({
        'status': 'UP',
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'version': os.getenv('APP_VERSION', '1.0.0')
    })

@app.route('/')
def hello():
    return 'Hello'

@app.route('/api/update-client', methods=['PUT'])
@login_required
def update_client():
    """Update an existing client's credentials"""
    data = request.json
    if not data:
        return jsonify({
            'status': 'ERROR',
            'message': 'No JSON data received'
        }), 400
    
    # Get client_id from session - only allow updating the authenticated client
    client_id = session.get('client_id')
    
    # Allow updates to these fields
    api_key = data.get('api_key')
    password = data.get('password')
    two_fa = data.get('two_fa')  # PAN card number
    vendor_info = data.get('vendor_info')
    client_code = data.get('client_code')
    
    # Load existing clients
    clients = load_clients()
    
    # Check if client exists
    if client_id not in clients:
        return jsonify({
            'status': 'ERROR',
            'message': 'Client not found'
        }), 404
    
    # Get current client data
    current_data = clients[client_id]
    
    # Update client data with new values if provided
    updated_data = {
        'api_key': api_key if api_key is not None else current_data['api_key'],
        'userid': current_data['userid'],  # Don't allow changing userid
        'password': password if password is not None else current_data.get('password', ''),
        'two_fa': two_fa if two_fa is not None else current_data['two_fa'],
        'vendor_info': vendor_info if vendor_info is not None else current_data['vendor_info'],
        'client_code': client_code if client_code is not None else current_data.get('client_code')
    }
    
    # Validate PAN card if provided
    if two_fa:
        pan_regex = r'^[A-Z]{5}[0-9]{4}[A-Z]{1}'
        if not re.match(pan_regex, two_fa):
            return jsonify({
                'status': 'ERROR',
                'message': 'Invalid PAN card format. It should be in the format ABCDE1234F'
            }), 400
    
    # Ensure vendor_info is same as userid if specified
    if vendor_info and vendor_info != current_data['userid']:
        updated_data['vendor_info'] = current_data['userid']
    
    # Save updated client data
    save_client(client_id, updated_data)
    
    # Re-initialize MOFSL client with updated credentials
    if client_id in mofsl_clients:
        # Remove the old client instance
        del mofsl_clients[client_id]
        # Get a new client instance
        get_mofsl_client(client_id)
    
    return jsonify({
        'status': 'SUCCESS',
        'message': 'Client credentials updated successfully'
    })

@app.route('/api/admin/update-client', methods=['PUT'])
def admin_update_client():
    """Admin endpoint to update any client's credentials"""
    data = request.json
    if not data:
        return jsonify({
            'status': 'ERROR',
            'message': 'No JSON data received'
        }), 400
    
    # Get client_id from request data
    client_id = data.get('client_id')
    if not client_id:
        return jsonify({
            'status': 'ERROR',
            'message': 'Client ID is required'
        }), 400
    
    # Allow updates to these fields
    api_key = data.get('api_key')
    userid = data.get('userid')
    password = data.get('password')
    two_fa = data.get('two_fa')  # PAN card number
    vendor_info = data.get('vendor_info')
    client_code = data.get('client_code')
    
    # Load existing clients
    clients = load_clients()
    
    # Check if client exists
    if client_id not in clients:
        return jsonify({
            'status': 'ERROR',
            'message': 'Client not found'
        }), 404
    
    # Get current client data
    current_data = clients[client_id]
    
    # Update client data with new values if provided
    updated_data = {
        'api_key': api_key if api_key is not None else current_data['api_key'],
        'userid': userid if userid is not None else current_data['userid'],
        'password': password if password is not None else current_data.get('password', ''),
        'two_fa': two_fa if two_fa is not None else current_data['two_fa'],
        'vendor_info': vendor_info if vendor_info is not None else current_data['vendor_info'],
        'client_code': client_code if client_code is not None else current_data.get('client_code')
    }
    
    # Validate PAN card if provided
    if two_fa:
        pan_regex = r'^[A-Z]{5}[0-9]{4}[A-Z]{1}'
        if not re.match(pan_regex, two_fa):
            return jsonify({
                'status': 'ERROR',
                'message': 'Invalid PAN card format. It should be in the format ABCDE1234F'
            }), 400
    
    # Ensure vendor_info is same as userid if specified
    if vendor_info and vendor_info != updated_data['userid']:
        updated_data['vendor_info'] = updated_data['userid']
    
    # Save updated client data
    save_client(client_id, updated_data)
    
    # Re-initialize MOFSL client with updated credentials
    if client_id in mofsl_clients:
        # Remove the old client instance
        del mofsl_clients[client_id]
    
    return jsonify({
        'status': 'SUCCESS',
        'message': 'Client credentials updated successfully'
    })


if __name__ == '__main__':
    # Enable debug mode for development
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(
        debug=debug_mode, 
        host='0.0.0.0', 
        port=int(os.getenv('PORT', 5005)),
        ssl_context=None if os.getenv('HTTPS_ENABLED', 'False').lower() != 'true' else 'adhoc'
    )