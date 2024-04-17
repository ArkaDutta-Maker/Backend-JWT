from flask import Flask, request, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager,get_jwt, create_access_token, get_current_user, jwt_required, get_jwt_identity,create_refresh_token, current_user
from flask_cors import CORS
from datetime import datetime, timezone, timedelta
import os
import redis
from sqlalchemy.sql import func

ACCESS_EXPIRES = timedelta(hours=0.5)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = ACCESS_EXPIRES
app.config["REDIS_PASSWORD"] = os.environ.get('REDIS_PASSWORD')
app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

jwt = JWTManager(app)
cors = CORS(app, origins="*", allow_headers="*")

jwt_redis_blocklist  = redis.Redis(
  host='redis-18953.c301.ap-south-1-1.ec2.cloud.redislabs.com',
  port=18953,
  password=app.config["REDIS_PASSWORD"],
   db=0, decode_responses=True)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

with app.app_context():
    db.create_all()

@jwt.expired_token_loader
def my_expired_token_callback(jwt_header, jwt_data):
    return jsonify({
        'error': 'TokenExpired',
        'message': 'The token has expired'
    }), 401

@jwt.invalid_token_loader
def my_invalid_token_callback(error):
    return jsonify({
        'error': 'Invalid token',
        'message': 'Signature verification failed'
    }), 401
@jwt.unauthorized_loader
def my_unauthorized_loader(error):
    return jsonify({
        'error': 'Unauthorized',
        'message': 'Request does not contain an access token'
    }), 401

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        form = request.get_json()
        name = form['name']
        email = form['email']
        hashed_password = bcrypt.generate_password_hash(form['password']).decode('utf-8')
        user = User.query.filter_by(email = email).first()
        if user:
            return jsonify({"error": "Email already exists"}), 400
        user = User(name= name,email=email, password = hashed_password)
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "User created successfully"}), 200
    return jsonify({"error": "Method not allowed"}), 405

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        form = request.get_json()
        email = form['email']
        password = form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            return jsonify({"token": create_access_token(identity=user.id), "refresh_token" : create_refresh_token(identity=user.id)}), 200
        else:
            return jsonify({"error": "Invalid email or password"}), 401
        
    return jsonify({"error": "Method not allowed"}), 405

@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    user = get_jwt_identity()
    access_token = create_access_token(identity=user)
    return jsonify(token=access_token)

@app.route("/user", methods=["GET"])
@jwt_required()
def user():

    return jsonify(
        id=current_user.id,
        name = current_user.name,
        email=current_user.email,
        password=current_user.password,
    )


# Callback function to check if a JWT exists in the database blocklist
@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload: dict):
    jti = jwt_payload["jti"]
    token_in_redis = jwt_redis_blocklist.get(jti)
    return token_in_redis is not None

@app.route("/logout", methods=["DELETE"])
@jwt_required(verify_type=False)
def logout():
    token = get_jwt()
    jti = token["jti"]
    ttype = token["type"]
    jwt_redis_blocklist.set(jti, "", ex=timedelta(hours=1))

    # Returns "Access token revoked" or "Refresh token revoked"
    return jsonify(msg=f"{ttype.capitalize()} token successfully revoked")