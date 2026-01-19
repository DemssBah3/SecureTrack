import pytest
from django.test import Client
from django.contrib.auth.models import User


@pytest.mark.django_db
class TestHealthCheck:
    """Tests du endpoint health check"""

    def test_health_endpoint_returns_200(self):
        """GET /api/health/ doit retourner 200 OK"""
        client = Client()
        response = client.get('/api/health/')
        assert response.status_code == 200

    def test_health_endpoint_returns_ok_status(self):
        """Response doit contenir status: ok"""
        client = Client()
        response = client.get('/api/health/')
        data = response.json()
        assert data['status'] == 'ok'

    def test_health_endpoint_has_message(self):
        """Response doit contenir message"""
        client = Client()
        response = client.get('/api/health/')
        data = response.json()
        assert 'message' in data


@pytest.mark.django_db
class TestIndexEndpoint:
    """Tests du endpoint index"""

    def test_index_endpoint_returns_200(self):
        """GET /api/ doit retourner 200 OK"""
        client = Client()
        response = client.get('/api/')
        assert response.status_code == 200

    def test_index_contains_app_name(self):
        """Response doit contenir app name"""
        client = Client()
        response = client.get('/api/')
        data = response.json()
        assert 'SecureTrack' in data['app']

    def test_index_contains_version(self):
        """Response doit contenir version"""
        client = Client()
        response = client.get('/api/')
        data = response.json()
        assert 'version' in data

    def test_index_contains_description(self):
        """Response doit contenir description"""
        client = Client()
        response = client.get('/api/')
        data = response.json()
        assert 'description' in data
