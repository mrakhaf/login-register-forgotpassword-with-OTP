from flask_login import UserMixin
from . import db

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(200))
    email = db.Column(db.String(120), unique=True)
    phone = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(120))
    # status = db.Column(db.Boolean)