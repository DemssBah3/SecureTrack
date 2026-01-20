"""
Pytest configuration and fixtures for SecureTrack project.
"""
import os
import sys
import django
from pathlib import Path

# Add src directory to Python path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "securetrack.settings")
django.setup()

import pytest
from django.test import Client
from django.contrib.auth.models import User


@pytest.fixture
def api_client():
    """
    Fixture pour un client HTTP Django.
    Utilisable dans les tests pour faire des requêtes.
    
    Exemple d'utilisation :
        def test_health_check(api_client):
            response = api_client.get('/api/health/')
            assert response.status_code == 200
    """
    return Client()


@pytest.fixture
def authenticated_user(db):
    """
    Fixture pour créer un utilisateur authentifié.
    Le décorateur @pytest.mark.django_db est implicite.
    
    Exemple d'utilisation :
        def test_user_logged_in(authenticated_user, api_client):
            assert authenticated_user.username == 'testuser'
    """
    user = User.objects.create_user(
        username='testuser',
        email='testuser@example.com',
        password='TestPassword123!'
    )
    return user
