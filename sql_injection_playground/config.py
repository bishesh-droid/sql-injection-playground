# sql_injection_playground/config.py

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """
    Configuration class for the Flask application.
    """
    # Flask secret key for session management. Crucial for security.
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY') or 'a_very_insecure_default_key_for_dev'

    # Path to the SQLite database file.
    # This will be created in the project root directory.
    DATABASE = os.path.join(os.path.abspath(os.path.dirname(os.path.dirname(__file__))), 'database.db')

    # Flag to indicate if the application is running in debug mode.
    # Should be False in production.
    DEBUG = os.environ.get('FLASK_DEBUG') == '1'

    # Ensure the secret key is set, especially in a production environment.
    if SECRET_KEY == 'a_very_insecure_default_key_for_dev':
        print("WARNING: FLASK_SECRET_KEY is not set in environment variables. Using a default, insecure key.")
        print("         Please set FLASK_SECRET_KEY in your .env file for production.")

