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
    
    # Secret key for session security (reads from environment or default)
    app.secret_key = os.getenv("FLASK_SECRET_KEY", "default_insecure_key_for_dev")
    
    # Enable CSRF Protection
    csrf.init_app(app)

    # Content Security Policy (CSP) tailored for Vercel Serverless & CDN assets
    csp = {
        'default-src': [
            '\'self\'',
        ],
        'script-src': [
            '\'self\'',
            '\'unsafe-inline\'', 
            'https://cdn.jsdelivr.net',
            'https://cdnjs.cloudflare.com'
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
            'data:',
            'https:'
        ],
        'connect-src': [
            '\'self\'',
            'https:'
        ]
    }

    # Initialize Talisman for security headers (force_https=False allows Vercel edge SSL termination)
    Talisman(app, content_security_policy=csp, force_https=False)
    
    app.register_blueprint(main_bp)
    return app

# Expose app globally for Vercel (@vercel/python) and Gunicorn
app = create_app()

if __name__ == "__main__":
    print("[SYSTEM] Neuro-Net AI Systems: ONLINE")
    app.run(debug=True, port=5000, threaded=True)
