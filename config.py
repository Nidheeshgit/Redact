import os

class Config:
    """Base configuration for the Flask application."""
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-please-change')
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'app.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REMEMBER_COOKIE_DURATION = 86400
