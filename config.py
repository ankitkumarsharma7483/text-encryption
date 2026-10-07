import os
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-only-secret"
    # Used to encrypt every key stored in the database (see encryption/key_manager.py)
    MASTER_KEY = os.environ.get("MASTER_KEY") or "dev-only-master-key"
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(BASE_DIR, "database.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    MAX_TEXT_LENGTH = 10_000
    RSA_KEY_BITS = 2048
