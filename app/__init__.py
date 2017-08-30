import os
import re

from flask_api import FlaskAPI
from flask_sqlalchemy import SQLAlchemy
from flask import session, request
from werkzeug.security import generate_password_hash
from flask import jsonify, make_response
from instance.config import app_config

db = SQLAlchemy()


from app.models import User, Bucketlist, Item

app = FlaskAPI(__name__, instance_relative_config=True)
app.config.from_object(app_config[os.getenv('APP_SETTINGS')])
app.config.from_pyfile('config.py')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

@app.errorhandler(404)
def page_not_found(error):
    response = {'message': 'Oops the page can not be found!!'}
    return make_response(jsonify(response)), 404
@app.errorhandler(405)
def method_not_alllowed(error):
    response = {'message': 'Oops the page can not be found!!'}
    return make_response(jsonify(response)), 404

@app.errorhandler(400)
def page_mulformed(error):
    response = {'message': 'Oops malformed url'}
    return make_response(jsonify(response)), 400


from app.auth import auth
from app.bucketlist import bucket
app.register_blueprint(auth)
app.register_blueprint(bucket)
