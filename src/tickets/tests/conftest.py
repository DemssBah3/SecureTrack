import pytest
from django.contrib.auth import get_user_model

User = get_user_model()

@pytest.fixture
def user(db):
    return User.objects.create_user(username='testuser', email='test@example.com', password='testpass123')

@pytest.fixture
def project(db, user):
    return Project.objects.create(name='Test Project', description='Test', created_by=user)
