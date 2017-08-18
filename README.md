[![Build Status](https://travis-ci.org/ogomb/RESTFULAPI_BUCKETLIST.svg?branch=master)](https://travis-ci.org/ogomb/RESTFULAPI_BUCKETLIST)[![Coverage Status](https://coveralls.io/repos/github/ogomb/RESTFULAPI_BUCKETLIST/badge.svg?branch=master)](https://coveralls.io/github/ogomb/RESTFULAPI_BUCKETLIST?branch=master)

# RESTFULAPI_BUCKETLIST

INTRODUCTION
This application provides RESTFUL endpoints to the bucketlist application.

FEATURES

A user can be able to signup.
A user can be able to login.

TECHNOLOGIES USED 

Flask mocroframework

Postgres database

HOW TO INSTALL THE APPLICATION

make a directory `mkdir bucketlist`

change directory to the created folder `cd bucketlist`

create virtual environment `virtualenv venv`

activate the virtual environment and install contents in the requirements file `pip install -r requirements.txt`

clone the repository `git clone https://github.com/ogomb/RESTFULAPI_BUCKETLIST.git` on the root folder.

export this files
  `export FLASK_APP="run.py"`
  
   `export APP_SETTINGS="development"`
   
   `export SECRET="some secret word"`
   
   `export DATABASE_URL=URL_TO_YOUR_DATABASE`
   
create postgres database 

`createdb YOURDATABASENAME`

`createdb test_apis`

Run the test using the following code `python test_apis.py`

Run the application using the following code `python run.py`
