"""
All of the application level configuration. Whatever the values that are
put in the .env file will be avaialble here and can be access using the 
Python environ object.
"""
from os import environ
from datetime import timedelta

JWT_SECRET_KEY = environ.get("SECRET_KEY")
SQLALCHEMY_DATABASE_URI = environ.get("SQLALCHEMY_DATABASE_URI")
SQLALCHEMY_TRACK_MODIFICATIONS = True
JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=5)
REDIS_HOST = environ.get("REDIS_HOST", "localhost")
REDIS_PORT = environ.get("REDIS_PORT", 6379)
