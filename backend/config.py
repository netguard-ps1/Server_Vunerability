import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'dev-jwt-secret-key-change-in-production')
    ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@example.com')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')
    FLASK_PORT = int(os.getenv('FLASK_PORT', 5000))
    CAPTURE_DIR = os.path.join(os.path.dirname(__file__), '..', 'captures')
    MAX_PACKETS_IN_MEMORY = 10000
    CORS_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"]
    
    @staticmethod
    def init_app():
        # Create captures directory if it doesn't exist
        os.makedirs(Config.CAPTURE_DIR, exist_ok=True)
