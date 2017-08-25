import unittest
import json
from app import create_app, db

class APITest(unittest.TestCase):
    """
    Class to test the restful api."""
    def setUp(self):
        """
        Function to set up the test. """
        self.app = create_app(config_name="testing")
        self.client = self.app.test_client

        self.user = {'username':'lewoh', 'email':'kenyan@gmail.com', 'password':'letmein'}
        self.bucketlist = {'name':'travel to taiwan'}
        self.item = {'itemname': 'buy clothes'}
        with self.app.app_context():
            db.session.close()
            db.drop_all()
            db.create_all()
    def test_signup(self):
        """Test user signup."""
        response = self.client().post('/auth/register', data=self.user)
        result = json.loads(response.data.decode())

        self.assertEqual(result['message'], 'Registered')
        self.assertEqual(response.status_code, 201)
    def test_empty_signup(self):
        """Test user signup."""
        response = self.client().post('/auth/register', data={'username':'','email':'','password':''})
        result = json.loads(response.data.decode())

        self.assertEqual(result['message'], 'You can not submit null values!')
        self.assertEqual(response.status_code, 201)
    def test_signup_characters(self):
        """Test user signup."""
        response = self.client().post('/auth/register', data={'username':'lw','email':'mbogo@gmail.com','password':'344234'})
        result = json.loads(response.data.decode())
        

        self.assertEqual(result['message'], 'username must be more than 8 characters')
        self.assertEqual(response.status_code, 201)
    def test_password_characters(self):
        """Test user signup."""
        response = self.client().post('/auth/register', data={'username':'lewis','email':'mbogo@gmail.com','password':'34'})
        result = json.loads(response.data.decode())
        

        self.assertEqual(result['message'], 'password must be more than 8 characters')
        self.assertEqual(response.status_code, 201)
    def test_email_characters(self):
        """Test user signup."""
        response = self.client().post('/auth/register', data={'username':'lewis','email':'mbogogmail.com','password':'34654'})
        result = json.loads(response.data.decode())
        

        self.assertEqual(result['message'], 'email has a bad format')
        self.assertEqual(response.status_code, 201)
    def test_username_characters(self):
        """Test user signup."""
        response = self.client().post('/auth/register', data={'username':'//lewis//','email':'mbogo@gmail.com','password':'34654'})
        result = json.loads(response.data.decode())
        

        self.assertEqual(result['message'], 'username can not contain special characters')
        self.assertEqual(response.status_code, 201)
    
    
    def test_user_exists(self):
        """Test if the user already exists."""
        response = self.client().post('/auth/register', data=self.user)
        self.assertEqual(response.status_code, 201)
        responseTwo = self.client().post('/auth/register', data=self.user)
        self.assertEqual(responseTwo.status_code, 202)
        result = json.loads(responseTwo.data.decode())
        self.assertEqual(result['message'], "User exists")
    def test_login(self):
        """Test user login functionality."""
        response = self.client().post('/auth/register', data=self.user)
        self.assertEqual(response.status_code, 201)
        loginresponse = self.client().post('/auth/login', data=self.user)
        result = json.loads(loginresponse.data.decode())
        self.assertEqual(result['message'], 'Logged In')
        self.assertEqual(loginresponse.status_code, 200)
        self.assertTrue(result['token'])

    def test_unregistered_user(self):
        """Test if the user is unregistered."""
        userDoesNotExist = {'username':'ogomb', 'email':'mkenyadaima@gmail.com', 'password':'password'}
        response = self.client().post('/auth/login', data=userDoesNotExist)
        result = json.loads(response.data.decode())
        self.assertEqual(response.status_code, 401)
        self.assertEqual(result['message'], 'username or password is incorrect')

    def user_registration(self, username="proffesor", email="prof@gmail.com", password="prof"):
        """A simple method to signup a user to be used in all the test cases that follow. """
        new_user = {'username': username, 'email':email, 'password':password}
        return self.client().post('/auth/register', data=new_user)
    def login_the_user(self, username='proffesor', password='prof'):
        """A simple method to login a user to be used in all the test cases that follow. """
        login_details = {'username':username, 'password':password}
        return self.client().post('/auth/login', data=login_details)
    def test_user_logout_with_token(self):
        """Test user logout."""
        self.user_registration()
        logged = self.login_the_user()
        token = json.loads(logged.data.decode())['token']
        response = self.client().get(
            '/auth/logout',
            headers=dict(Authorization="Bearer "+token))

        self.assertIn('you are logged out', str(response.data))
        self.assertEqual(response.status_code, 200)
    def test_user_logout_without_token(self):
        """Test user logout."""
        self.user_registration()
        logged = self.login_the_user()
        token = json.loads(logged.data.decode())['token']
        response = self.client().get(
            '/auth/logout',
            headers=dict(Authorization="Bearer "))

        self.assertIn('you were not logged in', str(response.data))
        self.assertEqual(response.status_code, 401)
    def test_user_changepassword(self):
        """Test user change password."""
        self.user_registration()
        logged = self.login_the_user()
        token = json.loads(logged.data.decode())['token']
        response = self.client().post(
            '/auth/reset_password',
            headers=dict(Authorization="Bearer "+token),
            data={'changepassword':'r3284712'})

        self.assertIn('the password has changed', str(response.data))
        self.assertEqual(response.status_code, 200)
    def test_user_notoken_changepassword(self):
        """Test user change password."""
        self.user_registration()
        logged = self.login_the_user()
        token = json.loads(logged.data.decode())['token']
        response = self.client().post(
            '/auth/reset_password',
            headers=dict(Authorization="Bearer "),
            data={'changepassword':''})

        self.assertIn('No token provided', str(response.data))
    
    def test_user_changenullpassword(self):
        """Test user change password."""
        self.user_registration()
        logged = self.login_the_user()
        token = json.loads(logged.data.decode())['token']
        response = self.client().post(
            '/auth/reset_password',
            headers=dict(Authorization="Bearer "+token),
            data={'changepassword':None})

        self.assertIn('password has not changed', str(response.data))
        

    def test_new_bucket_list(self):
        """Test the creation of a bucketlist."""
        self.user_registration()
        logged = self.login_the_user()
        token = json.loads(logged.data.decode())['token']
        response = self.client().post(
            '/bucketlists/',
            headers=dict(Authorization="Bearer "+token),
            data=self.bucketlist)
        self.assertEqual(response.status_code, 201)
        self.assertIn('travel to taiwan', str(response.data))
    def test_duplicate_bucket_list(self):
        """Test the creation of a bucketlist."""
        self.user_registration()
        logged = self.login_the_user()
        token = json.loads(logged.data.decode())['token']
        response = self.client().post(
            '/bucketlists/',
            headers=dict(Authorization="Bearer "+token),
            data=self.bucketlist)
        response2 = self.client().post(
            '/bucketlists/',
            headers=dict(Authorization="Bearer "+token),
            data=self.bucketlist)
        self.assertEqual(response2.status_code, 201)
        self.assertIn('bucketlist with that name exists', str(response2.data))

    

    def test_get_available_bucketlist(self):
        """Test the getting of the available bucketlist for a user."""
        self.user_registration()
        logged = self.login_the_user()
        token = json.loads(logged.data.decode())['token']
        response = self.client().post(
            '/bucketlists/',
            headers=dict(Authorization="Bearer "+token),
            data=self.bucketlist)
        self.assertEqual(response.status_code, 201)

        res = self.client().get(
            '/bucketlists/',
            headers=dict(Authorization="Bearer "+token),)
        self.assertEqual(res.status_code, 200)
        #self.assertIn('travel to taiwan', str(res.data))
    def test_querry_available_bucketlist(self):
        """Test the querry of the available bucketlist for a user."""
        self.user_registration()
        logged = self.login_the_user()
        token = json.loads(logged.data.decode())['token']
        response = self.client().post(
            '/bucketlists/',
            headers=dict(Authorization="Bearer "+token),
            data=self.bucketlist)
        self.assertEqual(response.status_code, 201)

        res = self.client().get(
            '/bucketlists/?q=lewis',
            headers=dict(Authorization="Bearer "+token))
        
        self.assertIn('Bucketlist not found', str(res.data))
    def test_getting_available_bucketlist(self):
        """Test the querry of the available bucketlist for a user."""
        self.user_registration()
        logged = self.login_the_user()
        token = json.loads(logged.data.decode())['token']
        response = self.client().post(
            '/bucketlists/',
            headers=dict(Authorization="Bearer "+token),
            data=self.bucketlist)
        self.assertEqual(response.status_code, 201)

        res = self.client().get(
            '/bucketlists/',
            headers=dict(Authorization="Bearer "+token))
        
        self.assertIn('1', str(res.data))
    def test_getting_available_bucketlist_no_token(self):
        """Test the querry of the available bucketlist for a user."""
        self.user_registration()
        logged = self.login_the_user()
        token = json.loads(logged.data.decode())['token']
        response = self.client().post(
            '/bucketlists/',
            headers=dict(Authorization="Bearer "+token),
            data=self.bucketlist)
        self.assertEqual(response.status_code, 201)

        res = self.client().get(
            '/bucketlists/',
            headers=dict(Authorization="Bearer "))
        
        self.assertIn('token not provided!', str(res.data))
    def test_get_bucketlist_having_an_id(self):
        """Testing getting a specific bucketlist based on the id."""
        self.user_registration()
        logged = self.login_the_user()
        token = json.loads(logged.data.decode())['token']

        response = self.client().post(
            '/bucketlists/',
            headers=dict(Authorization="Bearer "+token),
            data=self.bucketlist)

        self.assertEqual(response.status_code, 201)
        results = json.loads(response.data.decode())

        result = self.client().get(
            '/bucketlists/{}'.format(results['id']),
            headers=dict(Authorization="Bearer "+token))
        self.assertEqual(result.status_code, 200)
        self.assertIn('travel to taiwan', str(result.data))
    def test_edit_bucket(self):
        """Test editing the contents of a bucketlist."""
        self.user_registration()
        logged = self.login_the_user()
        token = json.loads(logged.data.decode())['token']

        response = self.client().post(
            '/bucketlists/',
            headers=dict(Authorization="Bearer "+ token),
            data={'name':'travel to vietnam'})
        self.assertEqual(response.status_code, 201)
        results = json.loads(response.data.decode())

        response = self.client().put(
            '/bucketlists/{}'.format(results['id']),
            headers=dict(Authorization="Bearer "+ token),
            data={
                "name": "travel to vietnam and learn of vietnamese war"
            })
        self.assertEqual(response.status_code, 200)
        results = self.client().get(
            '/bucketlists/{}'.format(results['id']),
            headers=dict(Authorization="Bearer "+token))
        self.assertIn('travel to vietnam', str(results.data))

    def test_delete_bucket(self):
        """Test deleting a bucketlist."""
        self.user_registration()
        logged = self.login_the_user()
        token = json.loads(logged.data.decode())['token']

        response = self.client().post(
            '/bucketlists/',
            headers=dict(Authorization="Bearer "+token),
            data={"name":"go to new york"})
        self.assertEqual(response.status_code, 201)

        results = json.loads(response.data.decode())

        res = self.client().delete(
            '/bucketlists/{}'.format(results['id']),
            headers=dict(Authorization="Bearer "+token),)
        self.assertEqual(res.status_code, 200)
        self.assertIn('The bucketlist is deleted', str(res.data))
        result = self.client().get(
            '/bucketlists/1',
            headers=dict(Authorization="Bearer "+token))
        self.assertEqual(result.status_code, 200)
        self.assertIn('The bucketlist does not exist', str(result.data))
    def test_create_item(self):
        """Test creating an item for a bucketlist."""
        self.user_registration()
        logged = self.login_the_user()
        token = json.loads(logged.data.decode())['token']

        response = self.client().post(
            '/bucketlists/',
            headers=dict(Authorization="Bearer "+token),
            data={"name":"travel to hong kong"})
        self.assertEqual(response.status_code, 201)
        results = json.loads(response.data.decode())
        res = self.client().post(
            '/bucketlists/{}/item'.format(results['id']),
            headers=dict(Authorization="Bearer "+token),
            data=self.item)
        self.assertEqual(res.status_code, 201)
        self.assertIn('buy clothes', str(res.data))

    def test_get_items(self):
        """Test get items for a bucketlist."""
        self.user_registration()
        logged = self.login_the_user()
        token = json.loads(logged.data.decode())['token']

        response = self.client().post(
            '/bucketlists/',
            headers=dict(Authorization="Bearer "+token),
            data={"name":"travel to hong kong"})
        self.assertEqual(response.status_code, 201)
        results = json.loads(response.data.decode())
        res = self.client().post(
            '/bucketlists/{}/item'.format(results['id']),
            headers=dict(Authorization="Bearer "+token),
            data=self.item)
        self.assertEqual(res.status_code, 201)
        self.assertIn('buy clothes', str(res.data))

        results2 = json.loads(res.data.decode())
        res = self.client().get(
            '/bucketlists/{}/item/{}'.format(results['id'], results2['id']),
            headers=dict(Authorization="Bearer "+token),)
        self.assertEqual(res.status_code, 200)
    def test_edit_item(self):
        """Test editing an item in a bucketlist."""
        self.user_registration()
        logged = self.login_the_user()
        token = json.loads(logged.data.decode())['token']

        response = self.client().post(
            '/bucketlists/',
            headers=dict(Authorization="Bearer "+token),
            data={"name":"travel to the US"})
        self.assertEqual(response.status_code, 201)
        results1 = json.loads(response.data.decode())

        res = self.client().post(
            '/bucketlists/{}/item'.format(results1['id']),
            headers=dict(Authorization="Bearer "+token),
            data=self.item)
        self.assertEqual(res.status_code, 201)

        result2 = json.loads(response.data.decode())
        res2 = self.client().put(
            '/bucketlists/{}/item/{}'.format(results1['id'], result2['id']),
            headers=dict(Authorization="Bearer "+token),
            data={"itemname":"buy clothes and shoes"})
        self.assertEqual(res2.status_code, 200)
        results3 = self.client().get(
            '/bucketlists/{}/item/{}'.format(results1['id'], result2['id']),
            headers=dict(Authorization="Bearer "+token))
        self.assertIn('and shoes', str(results3.data))

    def test_delete_an_item(self):
        """Test deleting an item in a bucketlist."""
        self.user_registration()
        logged = self.login_the_user()
        token = json.loads(logged.data.decode())['token']

        response = self.client().post(
            '/bucketlists/',
            headers=dict(Authorization="Bearer "+token),
            data={"name":"travel to the US"})
        self.assertEqual(response.status_code, 201)
        result = json.loads(response.data.decode())

        res = self.client().post(
            '/bucketlists/{}/item'.format(result['id']),
            headers=dict(Authorization="Bearer "+token),
            data=self.item)
        self.assertEqual(res.status_code, 201)
        result2 = json.loads(response.data.decode())
        response = self.client().delete(
            '/bucketlists/{}/item/{}'.format(result['id'], result2['id']),
            headers=dict(Authorization="Bearer "+token))
        self.assertEqual(response.status_code, 200)

        result3 = self.client().get(
            '/bucketlists/{}/item/{}',
            headers=dict(Authorization="Bearer "+token))
        self.assertEqual(result3.status_code, 404)
if __name__ == "__main__":
    unittest.main()
