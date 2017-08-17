from app import db

class User(db.Model):
    __tablename__ = 'User'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique= True)
    password = db.Column(db.String(80))
    bucketlists = db.relationship('Bucketlist', backref='author', lazy='dynamic')

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

    def save(self):
         db.session.add(self)
         db.session.commit()

    def __repr__(self):
        return '<User %r>' % self.username


class Bucketlist(db.Model):
    """This class represents the bucketlist table."""

    __tablename__ = 'bucketlists'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    user_name = db.Column(db.String(80), db.ForeignKey('User.username'))
    items = db.relationship('Item', backref='Bucketlist', lazy='dynamic')

    def __init__(self, name,user_name):
        """initialize with name."""
        self.name = name
        self.user_name=user_name

    def save(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_all():
        return Bucketlist.query.all()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        return "<Bucketlist: {}>".format(self.name)

class Item(db.Model):
    __tablename__ = 'Item'
    

    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(80), unique=True)
    bucket_name = db.Column(db.String(80), db.ForeignKey('bucketlists.name',onupdate="CASCADE"))

    def __init__(self, item_name, bucket_name):
        self.item_name = item_name
        self.bucket_name = bucket_name
        

    def __repr__(self):
        return '<Item %r>' % self.item_name