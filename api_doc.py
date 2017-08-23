import os
from flask import Flask, jsonify
from flasgger import Swagger

from app import create_app 

config_name = os.getenv('APP_SETTINGS')
app = create_app(config_name)
swagger = Swagger(app)

@app.route('/auth/register', methods=['POST'])
def registering():
    """Example endpoint creating a user
    This is using docstrings for specifications.
    ---
    parameters:
      - name: username
        in: formData
        type: string
        description: username
        required: true
      - name: email
        in: formData
        type: string
        description: user email
        required: true
      - name: password
        in: formData
        type: string
        description: user password
        required: true
   """
    pass
@app.route('/auth/login', methods=['POST'])
def login_in():
    """Example endpoint of loging in a user
    This is using docstrings for specifications.
    ---
    parameters:
      - name: username
        in: formData
        type: string
        description: user email
        required: true
      - name: password
        in: formData
        type: string
        description: user password
        required: true
    """
@app.route('/bucketlists/', methods=['POST'])
def createbucketlists():
    """Example endpoint of loging in a user
    This is using docstrings for specifications.
    ---
    parameters:
      - name: name
        in: formData
        type: string
        required: true
      - name: Authorization
        in: header
        description: an authorization header
        required: true
        type: string
    """
@app.route('/auth/logout', methods=['GET'])
def logoutuser():
    """Example endpoint of loging in a user
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        description: an authorization header
        required: true
        type: string 
    """
@app.route('/bucketlists/', methods=['GET'])
def getBucketlists():
    """Example endpoint of loging in a user
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        description: an authorization header
        required: true
        type: string
    responses:
      200:
        description: A list of bucketlists filtered for the user   
    """
@app.route('/bucketlists/<id>', methods=['GET'])
def getBucketlistsbyid():
    """Example endpoint of getting a specific bucketlist
    This is using docstrings for specifications.
    ---
    parameters:
      - name: id
        in: path
        type: int
        required: true
        description: id of bucketlist
      - name: Authorization
        in: header
        description: an authorization header
        required: true
        type: string
    responses:
      200:
        description: A bucketlist  
    """   
@app.route('/bucketlists/<id>', methods=['PUT'])
def editBucketlistsbyid():
    """Example endpoint of editing  a bucketlist
    This is using docstrings for specifications.
    ---
    parameters:
      - name: id
        in: path
        type: int
        required: true
        description: id of bucketlist
      - name: name
        in: formData
        type: string
        description: bucketlist updated info
        required: true
      - name: Authorization
        in: header
        description: an authorization header
        required: true
        type: string
    """   
@app.route('/bucketlists/<id>', methods=['DELETE'])
def deleteBucketlistsbyid():
    """Example endpoint of deleting  a bucketlist
    This is using docstrings for specifications.
    ---
    parameters:

      - name: Authorization
        in: header
        description: an authorization header
        required: true
        type: string
      - name: id
        in: path
        type: int
        required: true
        description: id of bucketlist
    """   
@app.route('/bucketlists/<id>/item', methods=['POST'])
def createItem():
    """Example endpoint of adding an item in a bucketlist
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        description: an authorization header
        required: true
        type: string
      - name: id
        in: path
        type: int
        required: true
        description: id of buckelist
      - name: itemname
        in: formData
        type: string
        required: true
        description: name of item
    """
@app.route('/bucketlists/<id>/item', methods=['GET'])
def getallitems():
    """Example endpoint of getting all items in a bucketlist
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        description: an authorization header
        required: true
        type: string
      - name: id
        in: path
        type: int
        required: true
        description: id of bucketlist
    """
@app.route('/bucketlists/<id>/item/<item_id>', methods=['GET'])
def getitem():
    """Example endpoint of getting a particular item in bucketlist
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        description: an authorization header
        required: true
        type: string
      - name: id
        in: path
        type: int
        required: true
        description: id of bucketlist
      - name: item_id
        in: path
        type: int
        required: true
        description: id of item
    """
@app.route('/bucketlists/<id>/item/<item_id>', methods=['PUT'])
def edititem():
    """Example endpoint of editing an item in bucketlist
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        description: an authorization header
        required: true
        type: string
      - name: id
        in: path
        type: int
        required: true
        description: id of bucketlist
      - name: item_id
        in: path
        type: int
        required: true
        description: id of item
      - name: itemname
        in: formData
        type: string
        required: true
    """
@app.route('/bucketlists/<id>/item/<item_id>', methods=['DELETE'])
def deleteitem():
    """Example endpoint of deleting an item from bucketlist
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        description: an authorization header
        required: true
        type: string
      - name: id
        in: path
        type: int
        required: true
        description: id of bucketlist
      - name: item_id
        in: path
        type: int
        description: id of item
        required: true
    """
app.run(debug= True)
