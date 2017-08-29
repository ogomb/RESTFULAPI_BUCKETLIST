[![Build Status](https://travis-ci.org/ogomb/RESTFULAPI_BUCKETLIST.svg?branch=master)](https://travis-ci.org/ogomb/RESTFULAPI_BUCKETLIST) [![Coverage Status](https://coveralls.io/repos/github/ogomb/RESTFULAPI_BUCKETLIST/badge.svg?branch=master)](https://coveralls.io/github/ogomb/RESTFULAPI_BUCKETLIST?branch=master)
# RESTFULAPI_BUCKETLIST
**INTRODUCTION**
This application provides RESTFUL endpoints to the bucketlist application.

**FEATURES**

A user can be able to signup.
A user can be able to login.

**TECHNOLOGIES USED** 

1. Flask mocroframework

2. Postgres database

**HOW TO INSTALL THE APPLICATION**

1. Make a directory `mkdir bucketlist`

2. change directory to the created folder `cd bucketlist`

3. create virtual environment `virtualenv venv`

4. activate the virtual environment and install contents in the requirements file `pip install -r requirements.txt`

5. clone the repository `git clone https://github.com/ogomb/RESTFULAPI_BUCKETLIST.git` on the root folder.

6. export this variables `source .env`
      
7. create postgres database 

`createdb YOURDATABASENAME` this should match DATABASE_URL DATABASE in .env file

`createdb test_api`

8. Run the test using the following code `python test_apis.py`

9. Run the application using the following code `python run.py`

**API ENDPOINTS**

Endpoint  | Public access
---------------------------|--------------
POST /auth/register | TRUE
POST /auth/login  | TRUE
POST /auth/logout  | TRUE
POST /auth/reset-password | TRUE
POST /bucketlists/  | FALSE
GET /bucketlists/  | FALSE
GET /bucketlists/<id> | FALSE
PUT /bucketlists/<id> | FALSE
DELETE /bucketlists/<id> | FALSE
POST /bucketlists/<id>/items/ | FALSE
PUT /bucketlists/<id>/items/<item_id> | FALSE
DELETE /bucketlists/<id>/items/<item_id> | FALSE
