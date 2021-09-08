from flask_login import UserMixin
from . import db
class User(UserMixin , db.Model):
    id = db.Column(db.Integer, primary_key = True)
    ustring = db.Column(db.String(100), nullable=False)
    userhash = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique = True)
    firstname = db.Column(db.String(100))
    dob = db.Column(db.Date)
    lastname = db.Column(db.String(100))
    password = db.Column(db.String(100))