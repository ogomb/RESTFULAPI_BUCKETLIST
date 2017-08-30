import os
import re

from flask_api import FlaskAPI
from flask_sqlalchemy import SQLAlchemy
from flask import session, request
from werkzeug.security import generate_password_hash
from flask import jsonify, make_response, Blueprint
from instance.config import app_config

from app.models import User, Bucketlist, Item
from app import app

bucket = Blueprint('bucket', __name__)

@bucket.route('/bucketlists', methods=['POST'])
def create_bucketlists():
    """This function is useful to create bucketlist.

    A url e.g /bucketlists/ will create the bucketlist of the given user
    the form data that is passed is the bucketlist name.
    """
    try:
        #check for precence of token in the header.
        header = request.headers.get('Authorization')
        token = header.split("Bearer ")[1]
        if token:
            username = User.token_decode(token)
            if not isinstance(username, str):
                if request.method == "POST":
                    name = str(request.data.get('name', '')).strip()
                    if set('[~!@#$%^&*()_+{}":;\']+$/').intersection(name):
                        response = {'message': 'bucketlist with special characters is disallowed'}
                        return make_response(jsonify(response)), 401
                    if len(name) < 5:
                        response = {'message': 'make your bucketlist descriptive'}
                        return make_response(jsonify(response)), 401
                    else:
                        gotbucket = Bucketlist.query.filter_by(name=name, username=username).first()
                        if gotbucket != None:
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
    except Exception:
        response = {'message': 'No token provided'}
        return make_response(jsonify(response)), 401

@bucket.route('/bucketlists/', methods=['GET'])
def get_bucketlists():
    """This function is useful to get bucketlist.
    One is able to search the bucketlist for a given string  like so /bucketlist?q=here

    One is able also to achieve pagination /bucketlist?page=1&limit=4 
    the above url is a depiction of pagination

    A url e.g /bucketlists/ will get the bucketlist of the given user
    the arguments of the function i.e id is the one gotten from the url route.
    """
    try:
        header = request.headers.get('Authorization')
        token = header.split("Bearer ")[1]
        if token:
            username = User.token_decode(token)
            if not isinstance(username, str):
                if request.method == "GET":
                    q = request.args.get('q', '').strip()
                    if q:
                        firstitem = Bucketlist.query.filter(Bucketlist.name.like("%"+q+"%"))\
                        .filter(Bucketlist.username == username).all()
                        if firstitem:
                            results = []
                            for fitem in firstitem:
                                obj = {
                                    'id': fitem.id,
                                    'name': fitem.name,
                                    'user_id': fitem.username
                                }
                                results.append(obj)
                            return make_response(jsonify(results)), 200
                        if not firstitem:
                            return jsonify({'message': 'Bucketlist not found'})
                    if request.args.get('page'):
                        page = int(request.args.get('page'))
                    else:
                        page = 1
                    limit = request.args.get('limit')
                    if limit and int(limit) < 8:
                        limit = int(request.args.get('limit'))
                    else:
                        limit = 4
                    bucketlists = Bucketlist.query.filter_by(username=username).\
                    paginate(page, limit, False)
                    if not bucketlists:
                        response = {'message':'no items available'}
                        return make_response(jsonify(response)), 404
                    if bucketlists.has_next:
                        next_page = '?page=' + str(
                            page + 1) + '&limit=' + str(limit)
                    else:
                        next_page = ""
                    if bucketlists.has_prev:
                        previous_page = '?page=' + str(
                            page - 1) + '&limit=' + str(limit)
                    else:
                        previous_page = ""
                    pagin_buckets = bucketlists.items
                    results = []
                    for bucketlist in pagin_buckets:
                        obj = {
                            'id': bucketlist.id,
                            'name': bucketlist.name,
                            'user_id': bucketlist.username
                        }
                        results.append(obj)
                    return make_response(jsonify({'next_url': next_page,'previous_page': \
                    previous_page,'result':results})), 200

            else:
                message = username
                response = {
                    'message':message
                }
                return make_response(jsonify(response)), 401
        else:
            response = {'message':"token not provided!"}
            return make_response(jsonify(response)), 401
    except Exception:
        response = {'message': 'No token provided'}
        return make_response(jsonify(response)), 401
@bucket.route('/bucketlists/<int:id>', methods=['DELETE'])
def bucketlist_delete(id):
    """This function is useful to delete a given bucketlist.
    One requires that the url contains the bucketlist id 
    The id required need to be correct i.e bucketlist id should belong to bucket the user owns
    
    e.g /bucketlists/1/item

    the arguments of the function i.e id is the one gotten from the url route.
    """
    try:
        header = request.headers.get('Authorization')
        token = header.split(" ")[1]
        if token:
            username = User.token_decode(token)
            if not isinstance(username, str):
                bucketlist = Bucketlist.query.filter_by(id=id, username=username).first()
                if not bucketlist:
                    return {
                        "message": "The bucketlist could not be deleted"
                        }, 200
                if request.method == "DELETE":
                    bucketlist.delete()
                    return {
                        "message": "The bucketlist is deleted"
                        }, 200

            else:
                response = {
                    'message': "problem with token login again"
                }
                return make_response(jsonify(response)), 401
    except Exception:
        response = {'message': 'No token provided'}
        return make_response(jsonify(response)), 401

@bucket.route('/bucketlists/<int:id>', methods=['PUT'])
def bucketlist_put(id):
    """This function is useful to edit  a given bucketlist.
    One requires that the url contains the bucketlist id 
    The id required need to be correct i.e bucketlist id should belong to bucket the user owns
    
    e.g /bucketlists/1

    the arguments of the function i.e id is the one gotten from the url route.
    name of the bucketlist also need to be passed as the form data to make the changes.
    """
    try:
        header = request.headers.get('Authorization')
        token = header.split(" ")[1]
        if token:
            username = User.token_decode(token)
            if not isinstance(username, str):
                bucketlist = Bucketlist.query.filter_by(id=id, username=username).first()
                if not bucketlist:
                    return {
                        "message": "The bucketlist could not be edited"
                        }, 200
                elif request.method == "PUT":
                    name = str(request.data.get('name', '')).strip()
                    if set('[~!@#$%^&*()_+{}":;\']+$/').intersection(name):
                        response = {'message': 'bucketlist with special characters is disallowed'}
                        return make_response(jsonify(response)), 401
                    if len(name) < 5:
                        response = {'message': 'make your bucketlist descriptive'}
                        return make_response(jsonify(response)), 401
                    else:
                        
                        bucketlist.name = name
                        bucketlist.save()
                        response = {
                            'name': bucketlist.name,
                            'username': bucketlist.username
                        }
                        return make_response(jsonify(response)), 200
            else:
                response = {
                    'message': "problem with token login again"
                }
                return make_response(jsonify(response)), 401
    except Exception:
        response = {'message': 'No token provided'}
        return make_response(jsonify(response)), 401
@bucket.route('/bucketlists/<int:id>', methods=['GET'])
def bucketlist_get_with_id(id):
    """This function is useful to get a given bucketlist.
    One requires that the url contains the bucketlist id 
    The id required need to be correct i.e bucketlist id should belong to bucket the user owns

    
    e.g /bucketlists/1

    the arguments of the function i.e id is the one gotten from the url route.
    """
    try:
        header = request.headers.get('Authorization')
        token = header.split(" ")[1]
        if token:
            username = User.token_decode(token)
             
            if not isinstance(username, str):
                bucketlist = Bucketlist.query.filter_by(id=id, username=username).first()
                if not bucketlist:
                    return {
                        "message": "The bucketlist does not exist"
                        }, 200
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
    except Exception:
        response = {'message': 'No token provided'}
        return make_response(jsonify(response)), 401
@bucket.route('/bucketlists/<int:id>/item', methods=['POST'])
def create_items(id):
    """This function is useful to post items of a given bucketlist.
    One requires that the url contains the bucketlist id
    The id required need to be correct i.e bucketlist id should belong to bucket the user owns
    e.g /bucketlists/1/item

    the arguments of the function i.e id is the one gotten from the url route.
    itemname, done are required inorder to make this route work.
    """
    try:
        header = request.headers.get('Authorization')
        token = header.split("Bearer ")[1]

        if token:
            username = User.token_decode(token)
            if not isinstance(username, str):
                if request.method == "POST":
                    itemname = str(request.data.get('itemname', '')).strip()
                    completed = request.data.get('done', '')
                    if  set('[~!@#$%^&*()_+{}":;\']+$').intersection(itemname):
                        response = {'message':'item name has a bad format'}
                        return make_response(jsonify(response)), 401
                    elif itemname == "":
                        response = {'message':'item name has a bad format'}
                        return make_response(jsonify(response)), 401
                    elif len(itemname) < 5:
                        response = {'message':'item name needs to be more descriptive'}
                        return make_response(jsonify(response)), 401

                    elif itemname:
                        try:
                            specificbucket = Bucketlist.query.\
                            filter_by(id=id, username=username).first()
                            
                            if specificbucket is None:
                                response = {'message':'You do not have such bucketlist'}
                                return make_response(jsonify(response)), 401


                            else:
                                item = Item.query.filter_by(item_name=itemname, bucket_id=id,\
                                username=username).first()
                                if item != None:
                                    response = {'message':'a simmilar item name exists'}
                                    return make_response(jsonify(response)), 201
                                else:

                                    item = Item(item_name=itemname, bucket_id=id, done=completed,\
                                    username=username)
                                    item.save()
                                    response = {
                                        'id': item.id,
                                        'name': item.item_name,
                                        'bucket_id': item.bucket_id,
                                        'done': item.done
                                    }
                                    return make_response(jsonify(response)), 201
                        except Exception:
                            response = {
                                'message': "bucket list id provided incorrect"
                            }
                            return make_response(jsonify(response)), 401
                    else:
                        response = {'message':'the item name has a bad format'}
                        return make_response(jsonify(response)), 401

            else:
                response = {
                    'message': 'problem with token login again'
                }
                return make_response(jsonify(response)), 401
    except Exception:
        response = {'message': 'No token provided'}
        return make_response(jsonify(response)), 401

@bucket.route('/bucketlists/<int:id>/item', methods=['GET'])
def get_items(id):
    """This function is useful to get items of a given bucketlist.
    One requires that the url contains the bucketlist id 
    The id required need to be correct i.e bucketlist id should belong to bucket the user owns

    One is able to search the bucketlist for a given string  like so /bucketlist/1/item?q=here

    One is able also to achieve pagination /bucketlist/1/item?page=1&limit=4 this is a depiction of pafination
    
    e.g /bucketlists/1/item

    the arguments of the function i.e id is the one gotten from the url route.
    """
    try:
        #make sure that the token id given before any further operations
        header = request.headers.get('Authorization')
        token = header.split("Bearer ")[1]
        if token:
            username = User.token_decode(token)
            if not isinstance(username, str):
                if request.method == "GET":
                    # search for item having the pattern as provided by the q paramete
                    q = request.args.get('q', '')
                    if q:
                        specificbucket = Bucketlist.query.filter_by(id=id, \
                        username=username).first()
                        if specificbucket is None:
                            response = {'message':'You do not own such bucketlist'}
                            return make_response(jsonify(response)), 401
                        else:

                            firstitem = Item.query.filter_by(bucket_id=id, \
                            username=username).filter(Item.item_name.like("%"+q+"%")).all()
                            if firstitem:
                                results = []
                                for item in firstitem:
                                    obj = {
                                        'id': item.id,
                                        'name': item.item_name,
                                        'bucket_id': item.bucket_id,
                                        'done' : item.done
                                    }
                                    results.append(obj)
                                return make_response(jsonify({'result':results})), 200
                            if not firstitem:
                                return jsonify({'message': 'item not found'})
                    # this is the functionality of pagination.
                    if request.args.get('page'):
                        page = int(request.args.get('page'))
                    else:
                        page = 1
                    limit = request.args.get('limit')
                    if limit and int(limit) < 8:
                        limit = int(request.args.get('limit'))
                    else:
                        limit = 1
                    specificbucket = Bucketlist.query.filter_by(id=id, username=username).first()
                    if specificbucket is None:
                        response = {'message':'You do not own such bucketlist'}
                        return make_response(jsonify(response)), 401
                    else:
                        items = Item.query.filter_by(bucket_id=id).paginate(page, limit, False)
                        if not items:
                            response = {'message':'no items available'}
                            return make_response(jsonify(response)), 404
                        if items.has_next:
                            next_page = '?page=' + str(
                                page + 1) + '&limit=' + str(limit)
                        else:
                            next_page = ""
                        if items.has_prev:
                            previous_page = '?page=' + str(
                                page - 1) + '&limit=' + str(limit)
                        else:
                            previous_page = ""
                        pagin_items = items.items
                        results = []
                        for item in pagin_items:
                            obj = {
                                'id': item.id,
                                'name': item.item_name,
                                'bucket_id': item.bucket_id,
                                'done': item.done
                            }
                            results.append(obj)
                        return make_response(jsonify({'next_url': next_page, \
                        'previous_page': previous_page, 'result':results})), 200
            else:
                message = username
                response = {
                    'message':'problem with token login again'
                }
                return make_response(jsonify(response)), 401
    except Exception:
        response = {'message': 'No token provided'}
        return make_response(jsonify(response)), 401
@bucket.route('/bucketlists/<int:id>/item/<int:item_id>', methods=['GET', 'PUT', 'DELETE'])
def itemedits(id, item_id):
    """This function is useful to get, edit and delete an item.
    One requires that the url contains the bucketlist id and item id
    The two id's required need to be correct i.e bucketlist id should belong to bucket the user owns
    
    e.g /bucketlists/1/item/1

    the arguments of the function id, and item_id are the ones gotten from the url route.
    when editing a particular item  itemname and done should also be passed as form data
    """
    try:
        # check if token exists if not notify the user of the need.
        header = request.headers.get('Authorization')
        token = header.split("Bearer ")[1]
        if token:
            username = User.token_decode(token)
            if not isinstance(username, str):
                try:
                    # querry for the bucketlist with the id belonging to the user.
                    specificbucket = Bucketlist.query.filter_by(id=id, username=username).first()
                    if specificbucket is None:
                        response = {'message':'You do not own such bucketlist'}
                        return make_response(jsonify(response)), 401
                    else:
                        items = Item.query.filter_by(id=item_id, \
                        bucket_id=id, username=username).first()
                        if not items:
                            return {
                                "message": "The item is not available"
                                }, 200
                        # if the method is a delete
                        if request.method == "DELETE":
                            items.delete()
                            return {
                                "message": "The item is deleted"
                                }, 200
                        elif request.method == "PUT":
                            itemname = str(request.data.get('itemname', '')).strip()
                            done = request.data.get('done', '').strip()
                            if itemname == "" or done == "":
                                response = {
                                    'message':'item name and done can not be blank'
                                    }
                                return make_response(jsonify(response)), 401
                            #check to see if the string contains special characters
                            if set('[~!@#$%^&*()_+{}":;\']+$').intersection(itemname):
                                response = {
                                    'message':'item name has bad format'
                                    }
                                return make_response(jsonify(response)), 401
                            if len(itemname) <5:
                                response = {
                                    'message':'item name needs to be more descriptive'
                                    }
                                return make_response(jsonify(response)), 401

                            items.item_name = itemname
                            items.done = done
                            items.save()
                            response = {
                                'name': items.item_name,
                                'bucket_id': id,
                                'done': items.done
                            }
                            return make_response(jsonify(response)), 200
                        #get the item with the given id
                        else:
                            response = {
                                'name': items.item_name,
                                'bucket_id': id,
                                'done': items.done
                            }
                            return make_response(jsonify(response)), 200
                except Exception:
                    response = {
                        'message': "problem with bucket id or item id"
                        }
                    return make_response(jsonify(response)), 401
                    
            else:
                response = {
                    'message': "problem with token login again"
                }
                return make_response(jsonify(response)), 401

    except Exception:
        response = {'message': 'No token provided'}
        return make_response(jsonify(response)), 401
