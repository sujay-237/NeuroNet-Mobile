import os
from flask import Flask
from app.routes import main_bp

def create_app():
    app = Flask(__name__, 
                template_folder='app/templates',
                static_folder='app/static') 
    
    # Set a secret key for security (reads from env or uses a default)
    app.secret_key = os.getenv("FLASK_SECRET_KEY", "default_insecure_key_for_dev")
    
    app.register_blueprint(main_bp)
    return app

# Initialize app globally for Gunicorn
app = create_app()

if __name__ == "__main__":
    print("[SYSTEM] Neuro-Net AI Systems: ONLINE")
    # In local dev, this runs. In production, Gunicorn uses the 'app' variable above.
    app.run(debug=True, port=5000, threaded=True)