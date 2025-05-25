from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from rest_framework import status
from django.urls import reverse

class AccountsTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpassword123',
            'password2': 'testpassword123',
            'first_name': 'Test',
            'last_name': 'User'
        }
        self.login_data = {
            'username': 'testuser',
            'password': 'testpassword123'
        }
        
    def test_register_user(self):
        url = reverse('register')
        response = self.client.post(url, self.user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue('token' in response.data)
        
    def test_login_user(self):
        # First register a user
        self.client.post(reverse('register'), self.user_data, format='json')
        
        # Then try to login
        url = reverse('login')
        response = self.client.post(url, self.login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue('token' in response.data)
        
    def test_user_detail(self):
        # Register and login
        register_response = self.client.post(
            reverse('register'), 
            self.user_data, 
            format='json'
        )
        token = register_response.data['token']
        
        # Set token in the header
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token}')
        
        # Get user details
        url = reverse('user-detail')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'testuser')
        
    def test_logout(self):
        # Register and login
        register_response = self.client.post(
            reverse('register'), 
            self.user_data, 
            format='json'
        )
        token = register_response.data['token']
        
        # Set token in the header
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token}')
        
        # Logout
        url = reverse('logout')
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK) 