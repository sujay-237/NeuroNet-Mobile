import os
from flask import Flask
from app.routes import main_bp
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman

# Initialize CSRF globally
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__, 
                template_folder='app/templates',
                static_folder='app/static') 
    
    # Set a secret key for security (reads from env or uses a default)
    app.secret_key = os.getenv("FLASK_SECRET_KEY", "default_insecure_key_for_dev")
    
    # Enable CSRF Protection
    csrf.init_app(app)

    # Define a strict Content Security Policy (CSP) to prevent XSS
    csp = {
        'default-src': [
            '\'self\'',
        ],
        'script-src': [
            '\'self\'',
            '\'unsafe-inline\'', 
            'https://cdn.jsdelivr.net' # Required for Bootstrap JS modals/dropdowns
        ],
        'style-src': [
            '\'self\'',
            '\'unsafe-inline\'',
            'https://fonts.googleapis.com',
            'https://cdn.jsdelivr.net',
            'https://cdnjs.cloudflare.com'
        ],
        'font-src': [
            '\'self\'',
            'https://fonts.gstatic.com',
            'https://cdnjs.cloudflare.com'
        ],
        'img-src': [
            '\'self\'',
            'data:'
        ]
    }

    # Initialize Talisman for security headers (force_https=False for local dev)
    Talisman(app, content_security_policy=csp, force_https=False)
    
    app.register_blueprint(main_bp)
    return app

# Initialize app globally for Gunicorn
app = create_app()

if __name__ == "__main__":
    print("[SYSTEM] Neuro-Net AI Systems: ONLINE")
    # In local dev, this runs. In production, Gunicorn uses the 'app' variable above.
    app.run(debug=True, port=5000, threaded=True)
