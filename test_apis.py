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
        self.assertEqual(result['message'], 'credentials are invalid')

    def user_registration(self, username="proffesor", email="prof@gmail.com", password="prof"):
        """A simple method to signup a user to be used in all the test cases that follow. """
        new_user = {'username': username, 'email':email, 'password':password}
        return self.client().post('/auth/register', data=new_user)
    def login_the_user(self, username='proffesor', password='prof'):
        """A simple method to login a user to be used in all the test cases that follow. """
        login_details = {'username':username, 'password':password}
        return self.client().post('/auth/login', data=login_details)

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

        result = self.client().get(
            '/bucketlists/1',
            headers=dict(Authorization="Bearer "+token))
        self.assertEqual(result.status_code, 404)
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
