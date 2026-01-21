import pytest
from django.test import Client
from django.contrib.auth import get_user_model

User = get_user_model()


@pytest.fixture
def api_client():
    """Django test client with session support"""
    return Client(enforce_csrf_checks=False)


@pytest.fixture
def authenticated_user(db, api_client):
    """Create a test user and authenticate"""
    user = User.objects.create_user(
        email='test@example.com',
        username='testuser',
        password='TestPassword123!',
    )
    user.totp_enabled = False
    user.totp_secret = ''
    user.failed_login_attempts = 0
    user.save()
    
    # Force authentication in the client
    api_client.force_login(user)
    
    return user


@pytest.fixture
def test_user(db):
    """Create a test user WITHOUT authenticating"""
    user = User.objects.create_user(
        email='test@example.com',
        username='testuser',
        password='TestPassword123!',
    )
    user.totp_enabled = False
    user.totp_secret = ''
    user.failed_login_attempts = 0
    user.save()
    
    return user


@pytest.fixture
def authenticated_user_with_2fa(db, api_client):
    """Create a test user with 2FA enabled"""
    user = User.objects.create_user(
        email='test2fa@example.com',
        username='testuser2fa',
        password='TestPassword123!',
    )
    user.totp_enabled = True
    user.totp_secret = 'JBSWY3DPEBLW64TMMQ======'  # Test secret
    user.failed_login_attempts = 0
    user.save()
    
    # Force authentication in the client
    api_client.force_login(user)
    
    return user