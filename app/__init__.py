import os
import re
from flask_api import FlaskAPI
from flask_sqlalchemy import SQLAlchemy
from flask import session, request
from werkzeug.security import generate_password_hash
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
        email = str(request.data['email']).strip()
        password = str(request.data['password']).strip()
        username = str(request.data['username']).strip()
        print username

        match = re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', email)
        if email == "" or password =="" or username == "":
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
        elif match == None:
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
                token = user.token_generation(user.id)
                if token:
                    response = {
                        'message': 'Logged In',
                        'token': token.decode()
                    }
                    return make_response(jsonify(response)), 200
            else:
                response = {
                    'message' : 'username or password is incorrect'
                }
                return make_response(jsonify(response)), 401
        except Exception as e:
            response = {
                'message': str(e)
            }
            return make_response(jsonify(response)), 500
    @app.route('/auth/logout', methods=['GET'])
    def logout():
        """Logout url """
        header = request.headers.get('Authorization')
        token = header.split("Bearer ")[1]
        if token:
            token1 = token[-8:]
            User.blacklisttoken(token1)
            print  User.expired_tokens
            response = {'message': 'you are logged out'}
            return make_response(jsonify(response)), 200
        if not token:
            response = {'message': 'you were not logged in'}
            return make_response(jsonify(response)), 401
    @app.route('/auth/reset_password', methods=['POST'])
    def reset_password():
        """reset password url """
        header = request.headers.get('Authorization')
        token = header.split("Bearer ")[1]
        if token:
            username = User.token_decode(token)
            if not isinstance(username, str):
                if request.method == "POST":
                    password = str(request.data.get('changepassword', ''))
                    if password:
                        hashedpass = generate_password_hash(password, 'sha256')
                        User.query.filter_by(id=username).update({'password': hashedpass})
                        db.session.commit()
                        response = {'message': 'the password has changed'}
                        return make_response(jsonify(response)), 200

                    else:
                        response = {'message': 'null values are not accepted'}
                        return make_response(jsonify(response))
            else:
                message = username
                response = {
                    'message':message
                }
                return make_response(jsonify(response)), 401
        else:
            response = {'message': 'No token provided'}
            return make_response(jsonify(response)), 401


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
                        bucket = Bucketlist.query.filter_by(name=name, username=username).first()
                        if bucket != None:
                            response = {'message': 'bucketlist with that name exists'}
                            return make_response(jsonify(response)), 201
                        else:
                            bucketlist = Bucketlist(name=name, username=username)
                            bucketlist.save()
                            response = jsonify({
                                'id': bucketlist.id,
                                'name': bucketlist.name,
                                'user_id': bucketlist.username
                            })
                            return make_response(response), 201
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
                    q = request.args.get('q', '')
                    if q:
                        firstitem = Bucketlist.query.filter_by(id=username, name=q).first()
                        print firstitem
                        if firstitem:
                            result = {}
                            results = []
                            result['id'] = firstitem.id
                            result['name'] = firstitem.name
                            result['bucket_name'] = firstitem.username
                            results.append(result)
                            print len(results)
                            return make_response(jsonify({'result':results})), 200
                        if not firstitem:
                            return jsonify({'message': 'Bucketlist not found'})
                    bucketlists = Bucketlist.query.filter_by(username=username)
                    results = []
                    for bucketlist in bucketlists:
                        obj = {
                            'id': bucketlist.id,
                            'name': bucketlist.name,
                            'user_id': bucketlist.username
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

    @app.route('/bucketlists/<int:id>', methods=['PUT'])
    def bucketlist_put(id, **kwargs):
        """ update a bucketlists."""
        header = request.headers.get('Authorization')
        token = header.split(" ")[1]
        if token:
            username = User.token_decode(token)
            if not isinstance(username, str):
                bucketlist = Bucketlist.query.filter_by(id=id).first()
                if not bucketlist:
                    abort(404)
                elif request.method == "PUT":
                    name = str(request.data.get('name', ''))
                    bucketlist.name = name
                    bucketlist.save()
                    response = {
                        'name': bucketlist.name,
                        'username': bucketlist.username
                    }
                    return make_response(jsonify(response)), 200
            else:
                message = username
                response = {
                    'message': message
                }
                return make_response(jsonify(response)), 401

    @app.route('/bucketlists/<int:id>', methods=['GET'])
    def bucketlist_get_with_id(id, **kwargs):
        """ get a bucketlist with a specific id."""
        header = request.headers.get('Authorization')
        token = header.split(" ")[1]
        if token:
            username = User.token_decode(token)
            print username
            if not isinstance(username, str):
                bucketlist = Bucketlist.query.filter_by(id=id).first()
                if not bucketlist:
                    abort(404)
                elif request.method == 'GET':
                    response = {
                        'name' : bucketlist.name,
                        'username': bucketlist.username
                    }
                    return make_response(jsonify(response)), 200

            else:
                message = username
                response = {
                    'message': message
                }
                return make_response(jsonify(response)), 401

    @app.route('/bucketlists/<int:id>/item', methods=['POST'])
    def create_items(id, **kwargs):
        """get and create items for a particular bucketlist."""
        header = request.headers.get('Authorization')
        token = header.split("Bearer ")[1]

        if token:
            username = User.token_decode(token)
            if not isinstance(username, str):
                if request.method == "POST":
                    itemname = str(request.data.get('itemname', ''))
                    if itemname:
                        item = Item.query.filter_by(item_name=itemname, bucket_id=id).first()
                        if item != None:
                            response = {'message':'a simmilar item name exists'}
                            return make_response(jsonify(response)), 201
                        else:

                            item = Item(item_name=itemname, bucket_id=id)
                            item.save()
                            response = {
                                'id': item.id,
                                'name': item.item_name,
                                'bucket_id': item.bucket_id
                            }
                            return make_response(jsonify(response)), 201
            else:
                message = username
                response = {
                    'message': message
                }
                return make_response(jsonify(response)), 401


    @app.route('/bucketlists/<int:id>/item', methods=['GET'])
    def get_items(id, **kwargs):
        """get and create items for a particular bucketlist."""
        header = request.headers.get('Authorization')
        token = header.split("Bearer ")[1]
        if token:
            username = User.token_decode(token)
            if not isinstance(username, str):
                if request.method == "GET":

                    q = request.args.get('q', '')
                    if q:
                        firstitem = Item.query.filter_by(bucket_id=id, item_name=q).first()
                        if firstitem:
                            result = {}
                            results = []
                            result['id'] = firstitem.id
                            result['name'] = firstitem.item_name
                            result['bucket_id'] = firstitem.bucket_id
                            results.append(result)
                            return make_response(jsonify({'result':results})), 200
                        if not firstitem:
                            return jsonify({'message': 'item not found'})
                    items = Item.query.filter_by(bucket_id=id).paginate(1, 3, False).items
                    results = []
                    for item in items:
                        obj = {
                            'id': item.id,
                            'name': item.item_name,
                            'bucket_id': item.bucket_id
                        }
                        results.append(obj)
                    return make_response(jsonify({'result':results})), 200
            else:
                message = username
                response = {
                    'message':message
                }
                return make_response(jsonify(response)), 401

    @app.route('/bucketlists/<int:id>/item/<int:item_id>', methods=['GET', 'PUT', 'DELETE'])
    def itemedits(id, item_id, **kwargs):
        """get, delete, edit items in a bucketlist."""
        header = request.headers.get('Authorization')
        token = header.split("Bearer ")[1]
        if token:
            username = User.token_decode(token)
            if not isinstance(username, str):
                items = Item.query.filter_by(id=item_id).first()
                if not items:
                    abort(404)
                if request.method == "DELETE":
                    items.delete()
                    return {
                        "message": "The item is deleted"
                        }, 200
                elif request.method == "PUT":
                    itemname = str(request.data.get('itemname', ''))
                    items.item_name = itemname
                    items.save()
                    response = {
                        'name': items.item_name,
                        'bucket_id': id
                    }
                    return make_response(jsonify(response)), 200
                else:
                    response = {
                        'name': items.item_name,
                        'bucket_id': id
                    }
                    return make_response(jsonify(response)), 200
            else:
                message = username
                response = {
                    'message': message
                }
                return make_response(jsonify(response)), 401


    return app
