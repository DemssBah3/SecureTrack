"""
Tests for the core API endpoints.
"""
import pytest
from django.test import Client


@pytest.mark.django_db
class TestHealthCheckEndpoint:
    """Tests for GET /api/health/ endpoint"""

    def test_health_check_returns_200(self, api_client):
        """Health check endpoint should return 200 OK"""
        response = api_client.get('/api/health/')
        assert response.status_code == 200

    def test_health_check_returns_json(self, api_client):
        """Health check should return JSON response"""
        response = api_client.get('/api/health/')
        data = response.json()
        assert isinstance(data, dict)

    def test_health_check_has_status_field(self, api_client):
        """Health check response should have 'status' field"""
        response = api_client.get('/api/health/')
        data = response.json()
        assert 'status' in data

    def test_health_check_has_service_field(self, api_client):
        """Health check response should have 'service' field"""
        response = api_client.get('/api/health/')
        data = response.json()
        assert 'service' in data


@pytest.mark.django_db
class TestIndexEndpoint:
    """Tests for GET /api/ endpoint"""

    def test_index_returns_200(self, api_client):
        """Index endpoint should return 200 OK"""
        response = api_client.get('/api/')
        assert response.status_code == 200

    def test_index_returns_json(self, api_client):
        """Index endpoint should return JSON response"""
        response = api_client.get('/api/')
        data = response.json()
        assert isinstance(data, dict)

    def test_index_has_message_field(self, api_client):
        """Index response should have 'message' field"""
        response = api_client.get('/api/')
        data = response.json()
        assert 'message' in data

    def test_index_has_version_field(self, api_client):
        """Index response should have 'version' field"""
        response = api_client.get('/api/')
        data = response.json()
        assert 'version' in data

    def test_index_has_status_field(self, api_client):
        """Index response should have 'status' field"""
        response = api_client.get('/api/')
        data = response.json()
        assert 'status' in data

    def test_index_message_contains_securetrack(self, api_client):
        """Index message should mention SecureTrack"""
        response = api_client.get('/api/')
        data = response.json()
        assert 'SecureTrack' in data['message']


@pytest.mark.django_db
class TestSecurityHeaders:
    """Tests for security headers in responses"""

    def test_health_check_has_x_frame_options(self, api_client):
        """Response should have X-Frame-Options header"""
        response = api_client.get('/api/health/')
        assert 'X-Frame-Options' in response

    def test_health_check_has_x_content_type_options(self, api_client):
        """Response should have X-Content-Type-Options header"""
        response = api_client.get('/api/health/')
        assert 'X-Content-Type-Options' in response

    def test_health_check_has_referrer_policy(self, api_client):
        """Response should have Referrer-Policy header"""
        response = api_client.get('/api/health/')
        assert 'Referrer-Policy' in response
