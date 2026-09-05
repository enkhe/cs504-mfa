import azure.functions as func
import os
import json
import secrets
import time
import datetime
from zoneinfo import ZoneInfo
import requests
import pyodbc
from werkzeug.security import check_password_hash, generate_password_hash

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

def get_db():
    conn_str = os.environ["AZURE_SQL_CONNECTIONSTRING"]
    return pyodbc.connect(conn_str)

def send_code(email, code):
    headers = {"api-key": os.environ["BREVO_API_KEY"], "content-type": "application/json"}
    payload = {
        "sender": {"name": os.environ["BREVO_SENDER_NAME"], "email": os.environ["BREVO_SENDER_EMAIL"]},
        "to": [{"email": email}],
        "subject": "Your login code",
        "textContent": f"Your code is {code}. It expires in 5 minutes."
    }
    try:
        answer = requests.post("https://api.brevo.com/v3/smtp/email", headers=headers, json=payload, timeout=10)
        return answer.status_code == 201
    except requests.RequestException:
        return False

@app.route(route="register", methods=["POST"])
def register(req: func.HttpRequest) -> func.HttpResponse:
    try:
        data = req.get_json()
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT Id FROM Users WHERE Username = ? OR Email = ?", (data['username'], data['email']))
            if cursor.fetchone():
                return func.HttpResponse(json.dumps({"error": "An account with this Username or Email already exists."}), status_code=400, mimetype="application/json")
            
            pwd_hash = generate_password_hash(data['password'])
            cursor.execute("""
                INSERT INTO Users (FirstName, LastName, Username, Email, PasswordHash, FailedAttempts) 
                VALUES (?, ?, ?, ?, ?, 0)
            """, (data['firstName'], data['lastName'], data['username'], data['email'], pwd_hash))
            conn.commit()
            return func.HttpResponse(json.dumps({"message": "Registered successfully"}), status_code=201, mimetype="application/json")
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500, mimetype="application/json")

@app.route(route="login", methods=["POST"])
def login(req: func.HttpRequest) -> func.HttpResponse:
    try:
        data = req.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        now = int(time.time())

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT Id, Email, PasswordHash, FailedAttempts, LockoutEnd, LastMfaSent 
                FROM Users 
                WHERE Username = ?
            """, (username,))
            user = cursor.fetchone()
            
            if not user:
                return func.HttpResponse(json.dumps({"error": "Invalid username or password."}), status_code=401, mimetype="application/json")

            user_id, email, pwd_hash, failed_attempts, lockout_end, last_mfa_sent = user

            if lockout_end and lockout_end > now:
                return func.HttpResponse(json.dumps({"error": f"Account locked due to too many failed attempts. Try again in {lockout_end - now} seconds."}), status_code=403, mimetype="application/json")

            if check_password_hash(pwd_hash, password):
                if last_mfa_sent and (now - last_mfa_sent) < 60:
                    return func.HttpResponse(json.dumps({"error": "An MFA code was recently sent. Please wait 60 seconds before trying again."}), status_code=429, mimetype="application/json")

                code = str(secrets.randbelow(900000) + 100000)
                expires = now + 300

                cursor.execute("""
                    UPDATE Users 
                    SET MfaCodeHash = ?, MfaCodeExpires = ?, LastMfaSent = ?, FailedAttempts = 0, LockoutEnd = NULL 
                    WHERE Id = ?
                """, (code, expires, now, user_id))
                conn.commit()
                
                if send_code(email, code):
                    return func.HttpResponse(json.dumps({"message": "MFA code sent"}), status_code=200, mimetype="application/json")
                return func.HttpResponse(json.dumps({"error": "Failed to dispatch MFA email."}), status_code=500, mimetype="application/json")
            
            else:
                failed_attempts += 1
                new_lockout = now + 900 if failed_attempts >= 5 else None
                
                cursor.execute("UPDATE Users SET FailedAttempts = ?, LockoutEnd = ? WHERE Id = ?", (failed_attempts, new_lockout, user_id))
                conn.commit()
                return func.HttpResponse(json.dumps({"error": "Invalid username or password."}), status_code=401, mimetype="application/json")

    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500, mimetype="application/json")

@app.route(route="resend", methods=["POST"])
def resend(req: func.HttpRequest) -> func.HttpResponse:
    try:
        data = req.get_json()
        username = data.get('username', '').strip()
        now = int(time.time())

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT Id, Email, LastMfaSent FROM Users WHERE Username = ?", (username,))
            user = cursor.fetchone()
            
            if not user:
                return func.HttpResponse(json.dumps({"error": "User profile not found."}), status_code=404, mimetype="application/json")
            
            user_id, email, last_mfa_sent = user
            
            # Rate limit the resend button to prevent email spamming
            if last_mfa_sent and (now - last_mfa_sent) < 60:
                return func.HttpResponse(json.dumps({"error": "Please wait 60 seconds before requesting a new code."}), status_code=429, mimetype="application/json")
                
            code = str(secrets.randbelow(900000) + 100000)
            expires = now + 300
            
            cursor.execute("""
                UPDATE Users 
                SET MfaCodeHash = ?, MfaCodeExpires = ?, LastMfaSent = ? 
                WHERE Id = ?
            """, (code, expires, now, user_id))
            conn.commit()
            
            if send_code(email, code):
                return func.HttpResponse(json.dumps({"message": "New MFA code dispatched."}), status_code=200, mimetype="application/json")
            return func.HttpResponse(json.dumps({"error": "Failed to dispatch MFA email."}), status_code=500, mimetype="application/json")
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500, mimetype="application/json")

@app.route(route="verify", methods=["POST"])
def verify(req: func.HttpRequest) -> func.HttpResponse:
    try:
        data = req.get_json()
        username = data.get('username', '').strip()
        code = data.get('code', '').strip()
        now = int(time.time())

        with get_db() as conn:
            cursor = conn.cursor()
            # Removed the expiration check from the SQL query to handle it in Python
            cursor.execute("""
                SELECT Id, MfaCodeHash, MfaCodeExpires
                FROM Users 
                WHERE Username = ?
            """, (username,))
            user = cursor.fetchone()
            
            if not user or not user[1]:
                return func.HttpResponse(json.dumps({"error": "No pending authentication found for this user."}), status_code=400, mimetype="application/json")
            
            user_id, stored_code, expires_at = user
            
            # 1. Verify the code matches exactly
            if stored_code != code:
                return func.HttpResponse(json.dumps({"error": "Invalid verification code."}), status_code=401, mimetype="application/json")
            
            # 2. Check if the matching code is expired
            if expires_at < now:
                return func.HttpResponse(json.dumps({"error": "Token expired. Request a new one or login again."}), status_code=401, mimetype="application/json")
                
            # Success: Clear code and issue session token
            cursor.execute("UPDATE Users SET MfaCodeHash = NULL, MfaCodeExpires = 0 WHERE Id = ?", (user_id,))
            
            token = secrets.token_hex(32)
            token_hash = generate_password_hash(token)
            session_expires = now + 604800 
            
            cursor.execute("""
                INSERT INTO UserSessions (UserId, RefreshTokenHash, ExpiresAt, IsRevoked) 
                VALUES (?, ?, ?, 0)
            """, (user_id, token_hash, session_expires))
            conn.commit()
            
            return func.HttpResponse(json.dumps({"message": "Login successful", "token": token}), status_code=200, mimetype="application/json")
            
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500, mimetype="application/json")

@app.route(route="viewotp/{username}", methods=["GET"])
def viewotp(req: func.HttpRequest) -> func.HttpResponse:
    username = req.route_params.get('username')
    now = int(time.time())
    
    if not username:
        return func.HttpResponse(json.dumps({"error": "Username required"}), status_code=400, mimetype="application/json")
        
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            # Filters strictly for unexpired codes. If it's in the past, no record is returned.
            cursor.execute("""
                SELECT MfaCodeHash, MfaCodeExpires 
                FROM Users 
                WHERE Username = ? AND MfaCodeExpires > ?
            """, (username, now))
            user = cursor.fetchone()
            
            if user and user[0]:
                mfa_code = user[0]
                expires_epoch = user[1]
                
                # Assigns UTC to the epoch conversion, then transforms to Pacific Time
                dt = datetime.datetime.fromtimestamp(expires_epoch, tz=datetime.timezone.utc)
                pt_dt = dt.astimezone(ZoneInfo("America/Los_Angeles"))
                formatted_expires = pt_dt.strftime('%Y-%m-%d %I:%M:%S %p')
                
                return func.HttpResponse(json.dumps({
                    "username": username,
                    "mfa_code": mfa_code,
                    "expires_at": formatted_expires
                }), status_code=200, mimetype="application/json")
            
            # Ambiguous error masks whether the user exists or the code simply expired
            return func.HttpResponse(json.dumps({
                "error": "User does not exist or no active one-time code available."
            }), status_code=404, mimetype="application/json")
            
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500, mimetype="application/json")

@app.route(route="viewotp1/{username}", methods=["GET"])
def viewotp1(req: func.HttpRequest) -> func.HttpResponse:
    username = req.route_params.get('username')
    if not username:
        return func.HttpResponse(json.dumps({"error": "Username required"}), status_code=400, mimetype="application/json")
        
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT MfaCodeHash, MfaCodeExpires FROM Users WHERE Username = ?", (username,))
            user = cursor.fetchone()
            
            if user and user[0]:
                mfa_code = user[0]
                expires_epoch = user[1]
                
                # Assigns UTC to the epoch conversion, then transforms directly to Pacific Time
                dt = datetime.datetime.fromtimestamp(expires_epoch, tz=datetime.timezone.utc)
                pt_dt = dt.astimezone(ZoneInfo("America/Los_Angeles"))
                formatted_expires = pt_dt.strftime('%Y-%m-%d %I:%M:%S %p PT')
                
                return func.HttpResponse(json.dumps({
                    "username": username,
                    "mfa_code": mfa_code,
                    "expires_at": formatted_expires
                }), status_code=200, mimetype="application/json")
            
            return func.HttpResponse(json.dumps({"error": "No active MFA code found for this user."}), status_code=404, mimetype="application/json")
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500, mimetype="application/json")