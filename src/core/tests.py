import pytest
from django.test import Client


@pytest.mark.django_db
class TestHealthCheckEndpoint:
    """Tests pour le health check endpoint"""

    def test_health_check_returns_200(self):
        client = Client()
        response = client.get('/api/health/')
        assert response.status_code == 200

    def test_health_check_returns_json(self):
        client = Client()
        response = client.get('/api/health/')
        data = response.json()
        assert isinstance(data, dict)

    def test_health_check_has_status_field(self):
        client = Client()
        response = client.get('/api/health/')
        data = response.json()
        assert 'status' in data

    def test_health_check_has_service_field(self):
        client = Client()
        response = client.get('/api/health/')
        data = response.json()
        assert 'service' in data


@pytest.mark.django_db
class TestIndexEndpoint:
    """Tests pour l'index endpoint"""

    def test_index_returns_200(self):
        client = Client()
        response = client.get('/api/')
        assert response.status_code == 200

    def test_index_returns_json(self):
        client = Client()
        response = client.get('/api/')
        data = response.json()
        assert isinstance(data, dict)

    def test_index_has_app_field(self):
        client = Client()
        response = client.get('/api/')
        data = response.json()
        assert 'app' in data

    def test_index_has_version_field(self):
        client = Client()
        response = client.get('/api/')
        data = response.json()
        assert 'version' in data

    def test_index_has_status_field(self):
        client = Client()
        response = client.get('/api/')
        data = response.json()
        assert 'status' in data

    def test_index_app_contains_securetrack(self):
        client = Client()
        response = client.get('/api/')
        data = response.json()
        assert 'SecureTrack' in data.get('app', '')


@pytest.mark.django_db
class TestSecurityHeaders:
    """Tests pour les headers de sécurité"""

    def test_health_check_has_x_frame_options(self):
        client = Client()
        response = client.get('/api/health/')
        assert 'X-Frame-Options' in response

    def test_health_check_has_x_content_type_options(self):
        client = Client()
        response = client.get('/api/health/')
        assert 'X-Content-Type-Options' in response

    def test_health_check_has_referrer_policy(self):
        client = Client()
        response = client.get('/api/health/')
        assert 'Referrer-Policy' in response
