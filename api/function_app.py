import azure.functions as func
import os
import json
import secrets
import time
import datetime
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
                return func.HttpResponse(json.dumps({"error": "Username or Email already exists"}), status_code=400, mimetype="application/json")
            
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
                return func.HttpResponse(json.dumps({"error": "Invalid username or password"}), status_code=401, mimetype="application/json")

            user_id, email, pwd_hash, failed_attempts, lockout_end, last_mfa_sent = user

            # Enforce account lockout
            if lockout_end and lockout_end > now:
                return func.HttpResponse(json.dumps({"error": f"Account locked. Try again in {lockout_end - now} seconds."}), status_code=403, mimetype="application/json")

            # Verify password
            if check_password_hash(pwd_hash, password):
                # Enforce 60-second MFA rate limit to prevent spam
                if last_mfa_sent and (now - last_mfa_sent) < 60:
                    return func.HttpResponse(json.dumps({"error": "MFA recently sent. Please wait 60 seconds."}), status_code=429, mimetype="application/json")

                # Generate plaintext code
                code = str(secrets.randbelow(900000) + 100000)
                expires = now + 300

                # Store plaintext code in database
                cursor.execute("""
                    UPDATE Users 
                    SET MfaCodeHash = ?, MfaCodeExpires = ?, LastMfaSent = ?, FailedAttempts = 0, LockoutEnd = NULL 
                    WHERE Id = ?
                """, (code, expires, now, user_id))
                conn.commit()
                
                if send_code(email, code):
                    return func.HttpResponse(json.dumps({"message": "MFA code sent"}), status_code=200, mimetype="application/json")
                return func.HttpResponse(json.dumps({"error": "Could not send MFA email"}), status_code=500, mimetype="application/json")
            
            else:
                # Handle failed attempt and trigger lockout if limit reached
                failed_attempts += 1
                new_lockout = now + 900 if failed_attempts >= 5 else None # 15 min lockout
                
                cursor.execute("UPDATE Users SET FailedAttempts = ?, LockoutEnd = ? WHERE Id = ?", (failed_attempts, new_lockout, user_id))
                conn.commit()
                return func.HttpResponse(json.dumps({"error": "Invalid username or password"}), status_code=401, mimetype="application/json")

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
            cursor.execute("""
                SELECT Id, MfaCodeHash 
                FROM Users 
                WHERE Username = ? AND MfaCodeExpires > ?
            """, (username, now))
            user = cursor.fetchone()
            
            # Direct plaintext comparison
            if user and user[1] and user[1] == code:
                user_id = user[0]
                
                cursor.execute("UPDATE Users SET MfaCodeHash = NULL, MfaCodeExpires = 0 WHERE Id = ?", (user_id,))
                
                token = secrets.token_hex(32)
                token_hash = generate_password_hash(token)
                expires_at = now + 604800 # 7 days
                
                cursor.execute("""
                    INSERT INTO UserSessions (UserId, RefreshTokenHash, ExpiresAt, IsRevoked) 
                    VALUES (?, ?, ?, 0)
                """, (user_id, token_hash, expires_at))
                conn.commit()
                
                return func.HttpResponse(json.dumps({"message": "Login successful", "token": token}), status_code=200, mimetype="application/json")
            
            return func.HttpResponse(json.dumps({"error": "Invalid or expired code"}), status_code=401, mimetype="application/json")
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500, mimetype="application/json")

@app.route(route="viewotp/{username}", methods=["GET"])
def viewotp(req: func.HttpRequest) -> func.HttpResponse:
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
                
                # Convert epoch to yyyy-MM-dd hh:mm:ss tt
                dt = datetime.datetime.fromtimestamp(expires_epoch)
                formatted_expires = dt.strftime('%Y-%m-%d %I:%M:%S %p')
                
                return func.HttpResponse(json.dumps({
                    "username": username,
                    "mfa_code": mfa_code,
                    "expires_at": formatted_expires
                }), status_code=200, mimetype="application/json")
            
            return func.HttpResponse(json.dumps({"error": "No active MFA code found"}), status_code=404, mimetype="application/json")
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500, mimetype="application/json")