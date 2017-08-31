import os
from datetime import datetime, timedelta
from app import db
import jwt

from werkzeug.security import generate_password_hash, check_password_hash


class User(db.Model):
    """A class that models a User object. a user has the username email, password
    The user object can have as many items as well as many buckelists.
    User also has a set of expired tokens which will contain tokens that have expired.

    methods include : __init(username, email, password)
                    is_password_valid(password)
                    save()
                    get_all()
                    blacklisttoken()
                    token_generation()
                    token_decode()
    """
    __tablename__ = 'User'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(255))
    bucketlists = db.relationship('Bucketlist', backref='User', lazy='dynamic')
    items = db.relationship('Item', backref='User', lazy='dynamic')
    expired_tokens = []

    def __init__(self, username, email, password):
        """constructor that initializes a user class.
        It is initialised by username, email and password."""
        self.username = username
        self.email = email
        self.password = generate_password_hash(password, method='sha256')

    def is_password_valid(self, password):
        """check if the password inputed is valid.
        the argument is passed and checked aganist the stored password"""
        return check_password_hash(self.password, password)

    def save(self):
        """save a user object.
        One call this method to save the user object to the database"""
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_all(username):
        """This method querries  all the bucketlist objects
        That the user has"""
        return User.query.filter_by(username=username)

    @staticmethod
    def blacklisttoken(token):
        """This method takes a token and adds it to  blacklisted tokens
        which is just a set."""
        User.expired_tokens.append(token)

    @staticmethod
    def checktokenset(token):
        """This method takes a token and checks if token is in the expired token set
        it return true or false depending if it is there."""
        if token in User.expired_tokens:
            return True
        else:
            return False
    def token_generation(self, id):
        """This method generates a token for the user.
        The token needs to be unique for every user is is a long string."""
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
        """This function tries to decode a token to see if it is valid.
        it first checks if it is blaclisted otherwise it decodes the token.
        """
        try:
            mytoken = token[-8:]
            if  User.checktokenset(mytoken):
                return 'Invalid token. Please login'
            else:
                load = jwt.decode(token, os.getenv('SECRET'))
                return load['user']
        except jwt.ExpiredSignatureError:
            return 'The token has expired. Login again'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please register and login'



    def __repr__(self):
        """to string representation of the user class.
        This is just a string that will be displayed if the user object is called."""
        return '<User %r>' % self.username


class Bucketlist(db.Model):
    """This class represents the bucketlist table.
    Bucketlist contains name and id
    methods include __init__(name, username)
                    save(),
                    getall(),
                    delete()
                    __repr__()
                    """

    __tablename__ = 'bucketlists'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    username = db.Column(db.Integer, db.ForeignKey(User.id))
    items = db.relationship('Item', backref='Bucketlist', lazy='dynamic')

    def __init__(self, name, username):
        """initialize bucketlist object. using the name and username as parameters"""
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
    item_name = db.Column(db.String(80))
    done = db.Column(db.Boolean, default=False)
    bucket_id = db.Column(db.Integer, db.ForeignKey('bucketlists.id'))
    username = db.Column(db.Integer, db.ForeignKey(User.id))

    def __init__(self, item_name, bucket_id, done, username):
        """initialize an item object."""
        self.item_name = item_name
        self.bucket_id = bucket_id
        self.done = done
        self.username = username
    def __getitem__(self, name):
        return self.id

    def save(self):
        """dave the item object to the database."""
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_all(bucketname):
        """get all the items belonging to the bucketlist."""
        return Item.query.filter_by(bucket_id=bucketname)

    def delete(self):
        """delete an item from a bucketlist."""
        db.session.delete(self)
        db.session.commit()
