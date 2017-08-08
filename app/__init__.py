from flask_api import FlaskAPI
from flask_sqlalchemy import SQLAlchemy

# local import
from instance.config import app_config

# initialize sql-alchemy
db = SQLAlchemy()

from flask import request, jsonify, abort

def create_app(config_name):
    from app.models import User

    app = FlaskAPI(__name__, instance_relative_config=True)
    app.config.from_object(app_config[config_name])
    app.config.from_pyfile('config.py')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)

    @app.route('/signup/', methods=['POST','GET'])
    def signup():
        if request.method == 'POST':
            username = str(request.data.get('username', ''))
            email = str(request.data.get('email', ''))
            password = str(request.data.get('password', ''))

            checkusername = User.query.filter_by(username =username).first()
            checkemail = User.query.filter_by(email=email).first()
            if not checkusername and not checkemail:
                user = User(username,email,password)
                user.save()
                response = jsonify({
                    'id' : user.id,
                    'username' : user.username,
                    'email' : user.email,
                    'password' : user.password
                    })
                response.status_code =200
                return response
            else:
                response = jsonify({'message': 'username or email already exists'})
                response.status_code =301
                return response
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
