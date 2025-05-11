import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'my-very-secret-key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
