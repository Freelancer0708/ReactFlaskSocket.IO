# app.py

from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, emit
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from flask_cors import CORS


app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app, cors_allowed_origins="*")
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
jwt = JWTManager(app)

USERS = {
    "user@example.com": bcrypt.generate_password_hash("password").decode('utf-8'),
}

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    if not password:
        return jsonify({"message": "Password must be non-empty."}), 400
    password = bcrypt.generate_password_hash(password).decode('utf-8')
    if email in USERS:
        return jsonify({"message": "User already exists."}), 400
    USERS[email] = password
    print(USERS)
    return jsonify({"message": "User created successfully."})

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    print(f"Users: {USERS}")  # Usersの中身を表示
    print(f"Attempting to authenticate user: {email}")  # 認証しようとしているユーザーを表示
    if USERS.get(email) and bcrypt.check_password_hash(USERS.get(email), password):
        access_token = create_access_token(identity=email, expires_delta=timedelta(minutes=30))
        return jsonify(access_token=access_token), 200
    else:
        print(f"Authentication failed for user: {email}")  # 認証失敗の情報を表示
        return jsonify({"message": "Invalid email or password."}), 401


@socketio.on('send_message')
@jwt_required()  # Require JWT to send messages
def handle_message(data):
    emit('message', data, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
