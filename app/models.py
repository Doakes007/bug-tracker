from . import db
from . import login_manager
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin, dev, qa, reporter

    # Relationships
    reported_bugs = db.relationship('Bug', backref='reporter', foreign_keys='Bug.created_by', lazy=True)
    assigned_bugs = db.relationship('Bug', backref='assignee', foreign_keys='Bug.assigned_to', lazy=True)


class Bug(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    steps_to_reproduce = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(10), nullable=False)  # Low, Medium, High, Critical
    status = db.Column(db.String(20), nullable=False, default="New")  # New, Assigned, etc.
    created_on = db.Column(db.DateTime, default=datetime.utcnow)

    # Foreign Keys
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    # ✅ Add this line
    history = db.relationship('BugHistory', backref='bug', lazy=True)
    comments = db.relationship('BugComment', backref='bug', lazy=True, cascade="all, delete-orphan")



# 🔐 Tell Flask-Login how to load a user from the DB
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
class BugHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bug_id = db.Column(db.Integer, db.ForeignKey('bug.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    old_status = db.Column(db.String(20))
    new_status = db.Column(db.String(20))
    comment = db.Column(db.Text)

    user = db.relationship('User')  # ✅ keep this
    # ❌ don't add: bug = db.relationship('Bug')


class BugComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bug_id = db.Column(db.Integer, db.ForeignKey('bug.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User')



