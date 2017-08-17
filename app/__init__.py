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
    @app.route('/auth/login', methods=['POST', 'GET'])
    def login():
        """Login route."""
        try:
            user = User.query.filter_by(username=request.data['username']).first()
            if user and user.is_password_valid(request.data['password']):
                token = user.token_generation(user.username)
                if token:
                    response = {
                        'message': 'Logged In',
                        'token': token.decode()
                    }
                    return make_response(jsonify(response)), 200
            else:
                response = {
                    'message' : 'credentials are invalid'
                }
                return make_response(jsonify(response)), 401
        except Exception as e:
            response = {
                'message': str(e)
            }
            return make_response(jsonify(response)), 500


    @app.route('/bucketlists/', methods=['POST'])
    def create_bucketlists():
        """create a bucketlist """
        header = request.headers.get('Authorization')
        token = header.split("Bearer ")[1]
        if token:
            username = User.token_decode(token)
            if not isinstance(username, str):
                if request.method == "POST":
                    name = str(request.data.get('name', ''))
                    if name:
                        bucketlist = Bucketlist(name=name, username=username)
                        bucketlist.save()
                        response = jsonify({
                            'id': bucketlist.id,
                            'name': bucketlist.name,
                            'user_id': bucketlist.username
                        })                       
                        return make_response(response),201
            else:
                message = username
                response = {
                    'message':message
                }
                return make_response(jsonify(response)), 401

    @app.route('/bucketlists/', methods=['GET'])
    def get_bucketlists():
        """Get all the buckelists."""
        header = request.headers.get('Authorization')
        token = header.split("Bearer ")[1]
        if token:
            username = User.token_decode(token)
            if not isinstance(username, str):
                if request.method == "GET":
                   
                    bucketlists = Bucketlist.query.filter_by(username=username)
                    results = []
                    for bucketlist in bucketlists:
                        obj = {
                            'id': bucketlist.id,
                            'name': bucketlist.name,
                            'user_name': bucketlist.username
                        }
                        results.append(obj)
                    return make_response(jsonify(results)), 200

            else:
                message = username
                response = {
                    'message':message
                }
                return make_response(jsonify(response)), 401
        else:
            abort(404)

    @app.route('/bucketlists/<int:id>', methods=['DELETE'])
    def bucketlist_delete(id, **kwargs):
        """ delete a bucketlists."""
        header = request.headers.get('Authorization')
        token = header.split(" ")[1]
        if token:
            username = User.token_decode(token)
            if not isinstance(username, str):
                bucketlist = Bucketlist.query.filter_by(id=id).first()
                if not bucketlist:
                    abort(404)
                if request.method == "DELETE":
                    bucketlist.delete()
                    return {
                        "message": "The bucketlist is deleted"
                        }, 200

            else:
                message = username
                response = {
                    'message': message
                }
                return make_response(jsonify(response)), 401

            
                
    

    return app
