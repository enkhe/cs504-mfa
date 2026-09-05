import azure.functions as func
import os, json, secrets, time, requests, pyodbc
from werkzeug.security import check_password_hash, generate_password_hash

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

def get_db():
    conn_str = os.environ["AZURE_SQL_CONNECTIONSTRING"]
    return pyodbc.connect(conn_str)

def send_brevo_email(email, code, is_reset=False):
    subject = "Password Reset Code" if is_reset else "Your login code"
    headers = {"api-key": os.environ["BREVO_API_KEY"], "content-type": "application/json"}
    payload = {
        "sender": {"name": os.environ["BREVO_SENDER_NAME"], "email": os.environ["BREVO_SENDER_EMAIL"]},
        "to": [{"email": email}],
        "subject": subject,
        "textContent": f"Your code is {code}. It expires in 5 minutes."
    }
    requests.post("https://api.brevo.com/v3/smtp/email", headers=headers, json=payload, timeout=10)

@app.route(route="register", methods=["POST"])
def register(req: func.HttpRequest) -> func.HttpResponse:
    data = req.get_json()
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT Id FROM Users WHERE Username = ? OR Email = ?", (data['username'], data['email']))
            if cursor.fetchone():
                return func.HttpResponse(json.dumps({"error": "User exists"}), status_code=400)
            
            pwd_hash = generate_password_hash(data['password'])
            cursor.execute("""
                INSERT INTO Users (FirstName, LastName, Username, Email, PasswordHash) 
                VALUES (?, ?, ?, ?, ?)
            """, (data['firstName'], data['lastName'], data['username'], data['email'], pwd_hash))
            conn.commit()
            return func.HttpResponse(json.dumps({"message": "Registered"}), status_code=201)
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
                send_brevo_email(user[0], code)
                return func.HttpResponse(json.dumps({"message": "MFA sent"}), status_code=200)
            return func.HttpResponse(json.dumps({"error": "Invalid login"}), status_code=401)
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
                cursor.execute("UPDATE Users SET MfaCodeHash = NULL WHERE Username = ?", (data['username'],))
                conn.commit()
                token = secrets.token_hex(32)
                return func.HttpResponse(json.dumps({"message": "Success", "token": token}), status_code=200)
            return func.HttpResponse(json.dumps({"error": "Invalid code"}), status_code=401)
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500)
