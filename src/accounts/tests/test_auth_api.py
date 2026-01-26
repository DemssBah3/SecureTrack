from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model

User = get_user_model()


class TestAuthAPI(APITestCase):
    """Tests pour les endpoints d'authentification"""

    def test_signup_success(self):
        """Test successful user signup"""
        response = self.client.post('/auth/signup/', {
            'email': 'test@example.com',
            'username': 'testuser',
            'password': 'SecurePass123!',
            'password_confirm': 'SecurePass123!'
        })
        assert response.status_code == status.HTTP_201_CREATED
        assert User.objects.filter(email='test@example.com').exists()

    def test_signup_weak_password(self):
        """Test signup with weak password"""
        response = self.client.post('/auth/signup/', {
            'email': 'test@example.com',
            'username': 'testuser',
            'password': '123',
            'password_confirm': '123'
        })
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_signup_password_mismatch(self):
        """Test signup with mismatched passwords"""
        response = self.client.post('/auth/signup/', {
            'email': 'test@example.com',
            'username': 'testuser',
            'password': 'SecurePass123!',
            'password_confirm': 'DifferentPass123!'
        })
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_signup_duplicate_email(self):
        """Test signup with existing email"""
        User.objects.create_user(
            email='existing@example.com',
            username='existing',
            password='SecurePass123!'
        )
        response = self.client.post('/auth/signup/', {
            'email': 'existing@example.com',
            'username': 'newuser',
            'password': 'SecurePass123!',
            'password_confirm': 'SecurePass123!'
        })
        # ✅ DOIT retourner 400 (email already exists)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_login_success(self):
        """Test successful login"""
        User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='SecurePass123!'
        )
        response = self.client.post('/auth/login/', {
            'email': 'test@example.com',
            'password': 'SecurePass123!'
        })
        assert response.status_code == status.HTTP_200_OK

    def test_login_invalid_credentials(self):
        """Test login with wrong password"""
        User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='SecurePass123!'
        )
        response = self.client.post('/auth/login/', {
            'email': 'test@example.com',
            'password': 'WrongPassword!'
        })
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_login_nonexistent_user(self):
        """Test login with nonexistent user"""
        response = self.client.post('/auth/login/', {
            'email': 'nonexistent@example.com',
            'password': 'SomePassword!'
        })
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_me_authenticated(self):
        """Test /me endpoint when authenticated"""
        user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='testpass'
        )
        self.client.force_authenticate(user=user)
        response = self.client.get('/auth/me/')
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data['email'] == 'test@example.com'
        assert data['username'] == 'testuser'

    def test_me_not_authenticated(self):
        """Test /me endpoint without authentication"""
        response = self.client.get('/auth/me/')
        # ✅ PEUT être 401 ou 403 selon CSRF
        assert response.status_code in [401, 403]

    def test_logout(self):
        """Test logout when authenticated"""
        user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='testpass'
        )
        self.client.force_authenticate(user=user)
        response = self.client.post('/auth/logout/')
        assert response.status_code == status.HTTP_200_OK

    def test_logout_not_authenticated(self):
        """Test logout without authentication"""
        response = self.client.post('/auth/logout/')
        # ✅ PEUT être 200 ou 403 selon CSRF
        assert response.status_code in [200, 403]
