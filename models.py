from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    
    # Tasks assigned to the user
    assigned_tasks = db.relationship('Task', foreign_keys='Task.assigned_to_id', backref='assigned_user', lazy='dynamic')
    
    # Tasks created by the user
    created_tasks = db.relationship('Task', foreign_keys='Task.created_by_id', backref='creator', lazy='dynamic')

    # Tasks reviewed by the user
    reviewed_tasks = db.relationship('Task', foreign_keys='Task.reviewed_by_id', backref='reviewer', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    comments = db.Column(db.Text, nullable=True)
    completion_percentage = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='working')  # working, review, submitted

    def __repr__(self):
        return f'<Task {self.title}>'
