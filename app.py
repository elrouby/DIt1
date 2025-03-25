from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_mysqldb import MySQL
import pyqrcode
import base64
import bcrypt
import qrcode
from io import BytesIO
import secrets

app = Flask(__name__)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'task1'
app.config['JWT_SECRET_KEY'] = 'your_secret_key'

mysql = MySQL(app)
jwt = JWTManager(app)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    twofa_secret = secrets.token_hex(16)
    
    cursor = mysql.connection.cursor()
    cursor.execute("INSERT INTO users (username, password, twofa_secret) VALUES (%s, %s, %s)", (username, hashed_password, twofa_secret))
    mysql.connection.commit()
    cursor.close()
    
    return jsonify({"message": "User registered successfully"})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT password FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()
    cursor.close()
    
    if user and bcrypt.checkpw(password.encode('utf-8'), user[0].encode('utf-8')):
        return jsonify({"message": "Login successful, scan QR for 2FA"})
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/qr', methods=['POST'])
def generate_qr():
    data = request.get_json()
    username = data['username']
    
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT twofa_secret FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()
    cursor.close()
    
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    secret_key = user[0]
    qr = qrcode.make(secret_key)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    
    return jsonify({"qr_code": qr_base64})

@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    data = request.get_json()
    username = data['username']
    provided_code = data['code']
    
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT twofa_secret FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()
    cursor.close()
    
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    if provided_code == user[0]: 
        access_token = create_access_token(identity=username)
        return jsonify({"message": "2FA verified", "access_token": access_token})
    else:
        return jsonify({"message": "Invalid 2FA code"}), 401

if __name__ == '__main__':
    app.run(debug=True)
