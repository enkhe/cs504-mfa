import azure.functions as func
import os, json, secrets, time, requests, pyodbc
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
    data = req.get_json()
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT Id FROM Users WHERE Username = ? OR Email = ?", (data['username'], data['email']))
            if cursor.fetchone():
                return func.HttpResponse(json.dumps({"error": "Username or Email already exists"}), status_code=400)
            
            pwd_hash = generate_password_hash(data['password'])
            cursor.execute("""
                INSERT INTO Users (FirstName, LastName, Username, Email, PasswordHash, MfaCodeHash, MfaCodeExpires) 
                VALUES (?, ?, ?, ?, ?, '', 0)
            """, (data['firstName'], data['lastName'], data['username'], data['email'], pwd_hash))
            conn.commit()
            return func.HttpResponse(json.dumps({"message": "Registered successfully"}), status_code=201)
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500)

@app.route(route="login", methods=["POST"])
def login(req: func.HttpRequest) -> func.HttpResponse:
    data = req.get_json()
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT Email, PasswordHash FROM Users WHERE Username = ?", (data['username'],))
            user = cursor.fetchone()
            
            if user and check_password_hash(user[1], data['password']):
                code = str(secrets.randbelow(900000) + 100000)
                code_hash = generate_password_hash(code)
                expires = int(time.time()) + 300
                
                cursor.execute("UPDATE Users SET MfaCodeHash = ?, MfaCodeExpires = ? WHERE Username = ?", (code_hash, expires, data['username']))
                conn.commit()
                
                if send_code(user[0], code):
                    return func.HttpResponse(json.dumps({"message": "MFA code sent"}), status_code=200)
                return func.HttpResponse(json.dumps({"error": "Could not send MFA email"}), status_code=500)
            return func.HttpResponse(json.dumps({"error": "Invalid username or password"}), status_code=401)
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500)

@app.route(route="verify", methods=["POST"])
def verify(req: func.HttpRequest) -> func.HttpResponse:
    data = req.get_json()
    now = int(time.time())
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT MfaCodeHash FROM Users WHERE Username = ? AND MfaCodeExpires > ?", (data['username'], now))
            user = cursor.fetchone()
            
            if user and user[0] and check_password_hash(user[0], data['code']):
                cursor.execute("UPDATE Users SET MfaCodeHash = NULL, MfaCodeExpires = 0 WHERE Username = ?", (data['username'],))
                conn.commit()
                
                # Generate a stateless session token for the frontend to store
                token = secrets.token_hex(32)
                return func.HttpResponse(json.dumps({"message": "Login successful", "token": token}), status_code=200)
            return func.HttpResponse(json.dumps({"error": "Invalid or expired code"}), status_code=401)
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500)
