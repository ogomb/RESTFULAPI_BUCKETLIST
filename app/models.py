import os
from datetime import datetime, timedelta
from app import db
import jwt

from werkzeug.security import generate_password_hash, check_password_hash


class User(db.Model):
    """A class that models a User object."""
    __tablename__ = 'User'
    

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(255))
    bucketlists = db.relationship('Bucketlist', backref='User', lazy='dynamic')
    expired_tokens = []

    def __init__(self, username, email, password):
        """constructor that initializes a user class."""
        self.username = username
        self.email = email
        self.password = generate_password_hash(password, method='sha256')
        
    
    

       

    def is_password_valid(self, password):
        """check if the password inputed is valid."""
        return check_password_hash(self.password, password)

    def save(self):
        """save a user object."""
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_all(username):
        """get all the bucketlist object."""
        return User.query.filter_by(username=username)

    @staticmethod
    def blacklisttoken(token):
        """add token to a blacklisted tokens"""
        User.expired_tokens.append(token)
        

    @staticmethod
    def checktTokenInList(token):
        """check if token is in the expired token lists"""
        for item in User.expired_tokens:
            if item == token:
                return True
            else:
                return False



    def token_generation(self, id):
        """generating a token for the user."""
        try:
            load = {
                'exp': datetime.utcnow() + timedelta(minutes=40),
                'user': id,
                'iat': datetime.utcnow()
                }
            token = jwt.encode(
                load,
                os.getenv('SECRET'),
                algorithm='HS256'
            )
            return token
        except Exception as e:
            return str(e)
    @staticmethod
    def token_decode(token):
        """decode a token to see if it is valid."""
        
        try:
            
            if  User.checktTokenInList(token):
                 return 'Invalid token. Please login'
            load = jwt.decode(token, os.getenv('SECRET'))
            return load['user']
        except jwt.ExpiredSignatureError:
            return 'The token has expired. Login again'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please register and login'



    def __repr__(self):
        """to string representation of the user class."""
        return '<User %r>' % self.username


class Bucketlist(db.Model):
    """This class represents the bucketlist table."""

    __tablename__ = 'bucketlists'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    username = db.Column(db.String(80), db.ForeignKey(User.username))
    items = db.relationship('Item', backref='Bucketlist', lazy='dynamic')

    def __init__(self, name, username):
        """initialize bucketlist object."""
        self.name = name
        self.username = username

    def save(self):
        """save a bucketlist object."""
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_all(username):
        """get all the bucketlist object."""
        return Bucketlist.query.filter_by(user_name=username)

    def delete(self):
        """delete a bucketlist object."""
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        """to string representation of the bucketlist object."""
        return "<Bucketlist: {}>".format(self.name)

class Item(db.Model):
    """item object."""
    __tablename__ = 'Item'
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(80), unique=True)
    bucket_name = db.Column(db.Integer, db.ForeignKey('bucketlists.id', onupdate="CASCADE"))

    def __init__(self, item_name, bucket_name):
        """initialize an item object."""
        self.item_name = item_name
        self.bucket_name = bucket_name
    def __getitem__(self, name):
        return self.id
        

    def save(self):
        """dave the item object to the database."""
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_all(bucketname):
        """get all the items belonging to the bucketlist."""
        return Item.query.filter_by(bucket_name=bucketname)

    def delete(self):
        """delete an item from a bucketlist."""
        db.session.delete(self)
        db.session.commit()




    
