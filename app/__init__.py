from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)

    # App configuration
    app.config['SECRET_KEY'] = 'your-secret-key'  # 🔐 Change this in production
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bugs.db'  # 💾 DB in project root
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize Flask extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'  # 👈 Redirect to login if not logged in

    # Register routes blueprint
    from .routes import main
    app.register_blueprint(main)

    return app

