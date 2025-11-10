"""Configuration management for the application"""
import os

class Config:
    """Application configuration"""
    
    # Secret key - required in production
    SECRET_KEY = os.environ.get('SECRET_KEY')
    
    # Database configuration
    DB_PATH = os.environ.get('DB_PATH', 'user_data.db')
    
    # Photo storage configuration
    PHOTOS_FOLDER = os.environ.get('PHOTOS_FOLDER', 'captured_photos')
    MAX_FILE_SIZE = int(os.environ.get('MAX_FILE_SIZE', 10485760))  # 10MB default
    
    # CORS configuration
    ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', '*').split(',')
    
    # Rate limiting configuration
    RATELIMIT_ENABLED = os.environ.get('RATELIMIT_ENABLED', 'true').lower() == 'true'
    RATELIMIT_STORAGE_URL = os.environ.get('RATELIMIT_STORAGE_URL', 'memory://')
    
    # Environment detection
    RAILWAY_ENV = any(key.startswith('RAILWAY_') for key in os.environ.keys())
    RENDER_ENV = 'RENDER' in os.environ
    IS_PRODUCTION = RAILWAY_ENV or RENDER_ENV
    
    # Flask environment
    FLASK_ENV = os.environ.get('FLASK_ENV', 'development' if not IS_PRODUCTION else 'production')
    
    @classmethod
    def validate(cls):
        """Validate configuration - raise error if required values are missing"""
        if cls.IS_PRODUCTION and not cls.SECRET_KEY:
            raise ValueError(
                "SECRET_KEY environment variable must be set in production. "
                "Please set it in your Railway/Render environment variables."
            )
        
        if cls.IS_PRODUCTION and '*' in cls.ALLOWED_ORIGINS:
            print("[WARNING] CORS is set to allow all origins (*) in production. "
                  "Consider setting ALLOWED_ORIGINS environment variable for better security.")

