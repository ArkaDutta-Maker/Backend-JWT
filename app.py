from flask import Flask, request, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager,get_jwt, create_access_token, get_current_user, jwt_required, get_jwt_identity,create_refresh_token, current_user
from flask_cors import CORS
from datetime import datetime, timezone
import os
from sqlalchemy.sql import func

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
jwt = JWTManager(app)
cors = CORS(app, origins="*", allow_headers="*")

class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    type = db.Column(db.String(16), nullable=False)
    user_id = db.Column(
        db.ForeignKey('user.id'),
        default=lambda: get_current_user().id,
        nullable=False,
    )
    created_at = db.Column(
        db.DateTime,
        server_default=func.now(),
        nullable=False,
    )

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
def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
    jti = jwt_payload["jti"]
    token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()

    return token is not None

@app.route("/logout", methods=["DELETE"])
@jwt_required(verify_type=False)
def modify_token():
    token = get_jwt()
    jti = token["jti"]
    ttype = token["type"]
    now = datetime.now(timezone.utc)
    db.session.add(TokenBlocklist(jti=jti, type=ttype, created_at=now))
    db.session.commit()
    return jsonify(msg=f"{ttype.capitalize()} token successfully revoked")