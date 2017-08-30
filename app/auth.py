import os
import re
from flask_api import FlaskAPI
from flask_sqlalchemy import SQLAlchemy
from flask import session, request
from werkzeug.security import generate_password_hash
from flask import jsonify, make_response, Blueprint
from instance.config import app_config
from app import db

from app.models import User, Bucketlist, Item

auth = Blueprint('auth', __name__)

@auth.route('/auth/logout', methods=['GET'])
def logout():
    """This method logs out a user from the system
    just take the token and store it in blacklisted tokens
    The token is sliced inorder to get the last 8 characters as they are changing 

    significantly.
    """
    header = request.headers.get('Authorization')
    token = header.split("Bearer ")[1]
    if token:
        token1 = token[-8:]
        User.blacklisttoken(token1)
        
        response = {'message': 'you are logged out'}
        return make_response(jsonify(response)), 200
    if not token:
        response = {'message': 'you were not logged in'}
        return make_response(jsonify(response)), 401
@auth.route('/auth/reset_password', methods=['POST'])
def reset_password():
    """This method changes the password of a user
    one needs to pass in the new password for the changes to take place
    
    the user also needs to be authenticated inorder to reach this endpoint
    that means he needs to have a token.
    
    changepassword = x
    where x is the password you want  to change to."""
    try:
        header = request.headers.get('Authorization')
        token = header.split("Bearer ")[1]
        if token:
            username = User.token_decode(token)
            if not isinstance(username, str):
                if request.method == "POST":
                    password = str(request.data.get('changepassword', '')).strip()
                    if len(password) < 8:
                        response = {'message': 'the password needs to be more than 8 characters'}
                        return make_response(jsonify(response)), 200

                    if password:
                        hashedpass = generate_password_hash(password, 'sha256')
                        User.query.filter_by(id=username).update({'password': hashedpass})
                        db.session.commit()
                        response = {'message': 'the password has changed'}
                        return make_response(jsonify(response)), 200

                    else:
                        response = {'message': 'password has not changed'}
                        return make_response(jsonify(response))
            else:
                message = username
                response = {
                    'message':'problem with token please login again'
                }
                return make_response(jsonify(response)), 401
        else:
            response = {'message': 'No token provided'}
            return make_response(jsonify(response)), 401
    except Exception:
        response = {'message': 'No token provided'}
        return make_response(jsonify(response)), 401


@auth.route('/auth/register', methods=['POST', 'GET'])
def register():
    """This endpoint is for registering a new user to the system
    one needs to pass in the username, email and password to the system

    the system check for edge cases to make sure that values being inputed are

    correctly parsed such as no blank form submissions.
    """
    try:

        email = str(request.data['email']).strip()
        password = str(request.data['password']).strip()
        username = str(request.data['username']).strip()
        match = re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', email)
        if email == "" or password == "" or username == "":
            response = {"message": "You can not submit null values!"}
            return make_response(jsonify(response)), 201
        elif len(username) < 3:
            response = {"message": "username must be more than 8 characters"}
            return make_response(jsonify(response)), 201
        elif len(password) < 3:
            response = {"message": "password must be more than 8 characters"}
            return make_response(jsonify(response)), 201

        elif set('[~!@#$%^&*()_+{}":;\']+$/').intersection(username):
            response = {'message': 'username can not contain special characters'}
            return make_response(jsonify(response)), 201
        elif match is None:
            response = {'message': 'email has a bad format'}
            return make_response(jsonify(response)), 201
        else:
            user = User.query.filter_by(email=request.data['email']).first()
            if not user:
                try:
                    data = request.data
                    email = data['email']
                    password = data['password']
                    username = data['username']
                    user = User(email=email, password=password, username=username)
                    user.save()

                    response = {'message': 'Registered'}
                    return make_response(jsonify(response)), 201
                except Exception:
                    response = {
                        'message': 'username is taken'
                    }
                    return make_response(jsonify(response)), 401
            else:
                response = {
                    'message': 'User exists'
                }
                return make_response(jsonify(response)), 202
    except Exception:
        response = {
            'message': 'some of the fields are missing'
        }
        return make_response(jsonify(response)), 400

@auth.route('/auth/login', methods=['POST', 'GET'])
def login():
    """This route logins the user and also gives him a token after succesful
    login.

    parameters include username and password
    they need to match what was registerd initially on the system.
    """
    try:
        username = request.data['username'].strip()
        password = request.data['password'].strip()

        if username and password:
            user = User.query.filter_by(username=request.data['username']).first()
            if user and user.is_password_valid(request.data['password']):
                token = user.token_generation(user.id)
                response = {
                    'message': 'Logged In',

                    'token': token.decode()
                }
                return make_response(jsonify(response)), 200
            else:
                response = {
                    'message': 'username or password is incorrect'
                    }
                return make_response(jsonify(response)), 401
        else:
            response = {
                'message': 'Either username or password is blank'
            }
            return make_response(jsonify(response)), 400

    except Exception:
        response = {
            'message': 'Either username or password is missing'
        }
        return make_response(jsonify(response)), 400
