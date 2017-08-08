import unittest
import os
import json
from app import create_app, db

class BucketlistTestCase(unittest.TestCase):
    """This class represents the bucketlist test case"""

    def setUp(self):
        """Define test variables and initialize app."""
        self.app = create_app(config_name="testing")
        self.client = self.app.test_client
        
        self.user = {'username':'lewoh', 'email':'kenyan@gmail.com','password':'letmein'}
        self.login_user ={'email':'kenyan@gmail.com', 'password': 'letmein'}
        # binds the app to the current context
        with self.app.app_context():
            # create all tables
            db.create_all()

    def test_user_signup(self):
        """Test API can create a user(POST request)"""
        res = self.client().post('/signup/', data=self.user)
        self.assertEqual(res.status_code, 200)
        self.assertIn('kenyan@gmail.com', str(res.data))

    def test_user_login(self):
        """Test API can login a user(POST request)"""
        res = self.client().post('/login/', data=self.login_user)
        self.assertDictContainsSubset(self.login_user, self.user)

    def tearDown(self):
        """teardown all initialized variables."""
        with self.app.app_context():
            # drop all tables
            db.session.remove()
            db.drop_all()

# Make the tests conveniently executable
if __name__ == "__main__":
    unittest.main()