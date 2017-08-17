import os
from flask_api import FlaskAPI
from flask_sqlalchemy import SQLAlchemy
from flask import session, request
from flask import jsonify, abort, make_response
from instance.config import app_config


db = SQLAlchemy()


def create_app(config_name):
    """ creating a flask app."""
    from app.models import User, Bucketlist, Item

    app = FlaskAPI(__name__, instance_relative_config=True)
    app.config.from_object(app_config[config_name])
    app.config.from_pyfile('config.py')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)

    @app.route('/auth/register', methods=['POST', 'GET'])
    def register():
        """ register route."""
        user = User.query.filter_by(username=request.data['username']).first()
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
            except Exception as e:
                response = {
                    'message': str(e)
                }
                return make_response(jsonify(response)), 401
        else:
            response = {
                'message': 'User exists'
            }
            return make_response(jsonify(response)), 202
    @app.route('/login/', methods=['POST', 'GET'])
    def login():
        if request.method == 'POST':
            data = request.get_json()
            email = str(request.data.get('email', ''))
            password = str(request.data.get('password',''))

            if not data:
                response = jsonify({'message': 'no info provided'})
                response.status_code = 401
                return response

            user = User.query.filter_by(email= email).first()
            if not user:
                return jsonify({'message': 'user does not exist'}), 401
            if password != user.password:
                return jsonify({'message': 'password does not match'}), 401
            
            response= jsonify({'message': 'You are logged in'})
            response.status_code = 200
            return response
                
    

    return app
