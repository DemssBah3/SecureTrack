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
from django.contrib.auth import get_user_model

User = get_user_model()


@pytest.fixture
def api_client():
    """
    Fixture pour un client HTTP Django.
    """
    return Client()


@pytest.fixture
def authenticated_user(db):
    """
    Fixture pour créer un utilisateur authentifié.
    Utilise le User model personnalisé.
    """
    user = User.objects.create_user(
        username='testuser',
        email='testuser@example.com',
        password='TestPassword123!'
    )
    return user