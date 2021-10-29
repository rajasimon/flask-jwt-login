"""
API application for the user registration. 

Application has three routes, which are registration, login, logout. Also
the API has the protected API to test the token based authentication system.
"""
# Third party packages
from datetime import timedelta

import redis

from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv

# This is responsible for loading the .env file
load_dotenv()

# Flask app instance
app = Flask(__name__)
app.config.from_pyfile("settings.py")
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Setup our redis connection for storing the blocklisted tokens. You will probably
# want your redis instance configured to persist data to disk, so that a restart
# does not cause your application to forget that a JWT was revoked.
jwt_redis_blocklist = redis.StrictRedis(
    host=app.config.get("REDIS_HOST"),
    port=app.config.get("REDIS_PORT"),
    db=0,
    decode_responses=True,
)


# Callback function to check if a JWT exists in the redis blocklist
@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token_in_redis = jwt_redis_blocklist.get(jti)
    return token_in_redis is not None


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100))
    name = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def __str__(self):
        return f"{self.id} - {self.username} - {self.name}"


@app.route("/")
def index():
    """
    Route to return the name of the application
    """
    return {"Name": "DevOpsEnabler"}


@app.route("/registration", methods=["POST"])
def registration_view():
    """
    Accept email and password to register the user.
    """
    email = request.json.get("email")
    password = request.json.get("password")
    name = request.json.get("name")

    # If existing user found for this user return the error
    user = User.query.filter_by(email=email).first()
    if user:
        return {"status": False, "message": "User is already registered."}

    # Create the user object with the hashed password.
    gen_password = generate_password_hash(password, method="sha256")
    user = User(email=email, password=gen_password, name=name)
    db.session.add(user)
    db.session.commit()
    return {"status": True, "message": "User is created successfully."}, 201


@app.route("/login", methods=["POST"])
def login_view():
    """
    Log the user in by providing the jwt token
    """
    email = request.json.get("email")
    password = request.json.get("password")

    user = User.query.filter_by(email=email).first()
    if check_password_hash(user.password, password):
        access_token = create_access_token(identity=email)
        return {
            "status": True,
            "message": "Access token generated",
            "access_token": access_token,
        }, 200
    return {"status": False, "error": "Provided password is not matched"}, 401


@app.route("/logout", methods=["DELETE"])
@jwt_required()
def logout_view():
    """
    Logout using the blocklist
    """
    jti = get_jwt()["jti"]
    jwt_redis_blocklist.set(jti, "", ex=timedelta(minutes=5))
    return {"status": True, "message": "Access token revoked"}


@app.route("/profile", methods=["GET"])
@jwt_required()
def profile():
    """
    Testing the JWT token is working or not.
    """
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user).first()
    return {"logged_in_as": current_user, "name": user.name}, 200
