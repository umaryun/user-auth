import unittest
from datetime import timedelta

from app import app, create_token



class AuthTest(unittest.TestCase):

    def setUp(self):
        app.config['TESTING'] = True
        self.app = app.test_client()
        self.db = app.config['SQLALCHEMY_DATABASE_URI']

    def tearDown(self):
        pass

    def test_token_generation(self):
        user = app.User(email='test@example.com', password='password')
        access_token = create_token(identity=user.id)

        # Decode the token and verify user details
        payload = jwt.decode(access_token, app.config['JWT_SECRET_KEY'])
        self.assertEqual(payload['sub'], user.id)

        # Check token expiration (set expiry to 1 minute for testing)
        self.assertTrue(payload['exp'] > (datetime.utcnow() + timedelta(minutes=1)).timestamp())

    def test_user_access_control(self):
        user1 = User(email='user1@example.com', password='password1')
        user2 = User(email='user2@example.com', password='password2')
        org1 = Organization(name='Org 1')
        user1.organizations.append(org1)

        db.session.add(user1)
        db.session.add(user2)
        db.session.commit()

        # Login user1 and access user2 details (unauthorized)
        token = create_token(identity=user1.id)
        response = self.app.get(f'/api/users/{user2.id}', headers={'Authorization': f'Bearer {token}'})
        self.assertEqual(response.status_code, 403)

    def test_register_success(self):
        data = {
            'firstName': 'John',
            'lastName': 'Doe',
            'email': 'john.doe@example.com',
            'password': 'password',
        }
        response = self.app.post('/auth/register', json=data)

        self.assertEqual(response.status_code, 201)
        data = response.get_json()
        self.assertIn('accessToken', data)
        self.assertEqual(data['user']['firstName'], 'John')
        self.assertEqual(data['user']['name'], 'John\'s Organisation')  # Verify organization name

    def test_register_validation_errors(self):
        # Missing fields
        for field in ['firstName', 'lastName', 'email', 'password']:
            data = {'email': 'john.doe@example.com', 'password': 'password'}
            del data[field]
            response = self.app.post('/auth/register', json=data)
            self.assertEqual(response.status_code, 422)

        # Duplicate email
        data = {
            'firstName': 'John',
            'lastName': 'Doe',
            'email': 'john.doe@example.com',
            'password': 'password',
        }
        user = User(**data)
        db.session.add(user)
        db.session.commit()

        response = self.app.post('/auth/register', json=data)
        self.assertEqual(response.status_code, 422)

        db.session.delete(user)
        db.session.commit()

    def test_login_success(self):
        user = User(email='john.doe@example.com', password='password')
        db.session.add(user)
        db.session.commit()

        data = {'email': 'john.doe@example.com', 'password': 'password'}
        response = self.app.post('/auth/login', json=data)

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('accessToken', data)
        self.assertEqual(data['user']['email'], 'john.doe@example.com')

    def test_login_failure(self):
        data = {'email': 'john.doe@example.com', 'password': 'wrong_password'}
        response = self.app.post('/auth/login', json=data)

