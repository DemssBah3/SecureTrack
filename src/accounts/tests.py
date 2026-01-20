"""
Tests for authentication endpoints.
Tests pour signup, login, logout, me endpoints.
"""
import pytest
from django.test import Client
from django.contrib.auth import get_user_model

User = get_user_model()


@pytest.mark.django_db
class TestSignup:
    """Tests pour l'endpoint POST /auth/signup/"""

    def test_signup_with_valid_data(self, api_client):
        """Signup avec données valides doit créer un user"""
        response = api_client.post('/auth/signup/', {
            'email': 'newuser@example.com',
            'username': 'newuser',
            'password': 'SecurePassword123!',
            'password_confirm': 'SecurePassword123!',
        })
        
        assert response.status_code == 201
        data = response.json()
        assert data['status'] == 'success'
        assert data['user']['email'] == 'newuser@example.com'
        assert data['user']['username'] == 'newuser'
        
        # Vérifier que l'user a été créé en DB
        assert User.objects.filter(email='newuser@example.com').exists()

    def test_signup_with_duplicate_email(self, api_client, authenticated_user):
        """Signup avec email déjà existant doit échouer"""
        response = api_client.post('/auth/signup/', {
            'email': authenticated_user.email,  # Email du user de test
            'username': 'another_user',
            'password': 'SecurePassword123!',
            'password_confirm': 'SecurePassword123!',
        })
        
        assert response.status_code == 400
        data = response.json()
        assert data['status'] == 'error'
        assert 'email' in data['errors']

    def test_signup_with_duplicate_username(self, api_client, authenticated_user):
        """Signup avec username déjà existant doit échouer"""
        response = api_client.post('/auth/signup/', {
            'email': 'different@example.com',
            'username': authenticated_user.username,  # Username du user de test
            'password': 'SecurePassword123!',
            'password_confirm': 'SecurePassword123!',
        })
        
        assert response.status_code == 400
        data = response.json()
        assert data['status'] == 'error'
        assert 'username' in data['errors']

    def test_signup_with_mismatched_passwords(self, api_client):
        """Signup avec passwords qui ne correspondent pas doit échouer"""
        response = api_client.post('/auth/signup/', {
            'email': 'newuser@example.com',
            'username': 'newuser',
            'password': 'SecurePassword123!',
            'password_confirm': 'DifferentPassword123!',
        })
        
        assert response.status_code == 400
        data = response.json()
        assert data['status'] == 'error'

    def test_signup_with_weak_password(self, api_client):
        """Signup avec mot de passe faible doit échouer"""
        response = api_client.post('/auth/signup/', {
            'email': 'newuser@example.com',
            'username': 'newuser',
            'password': '123',  # Trop court
            'password_confirm': '123',
        })
        
        assert response.status_code == 400
        data = response.json()
        assert data['status'] == 'error'

    def test_signup_with_missing_email(self, api_client):
        """Signup sans email doit échouer"""
        response = api_client.post('/auth/signup/', {
            'username': 'newuser',
            'password': 'SecurePassword123!',
            'password_confirm': 'SecurePassword123!',
        })
        
        assert response.status_code == 400
        data = response.json()
        assert data['status'] == 'error'

    def test_signup_with_invalid_email(self, api_client):
        """Signup avec email invalide doit échouer"""
        response = api_client.post('/auth/signup/', {
            'email': 'not-an-email',
            'username': 'newuser',
            'password': 'SecurePassword123!',
            'password_confirm': 'SecurePassword123!',
        })
        
        assert response.status_code == 400
        data = response.json()
        assert data['status'] == 'error'

    def test_signup_password_hashed_in_db(self, api_client):
        """Le mot de passe doit être hashé en DB, pas en clair"""
        password = 'SecurePassword123!'
        response = api_client.post('/auth/signup/', {
            'email': 'newuser@example.com',
            'username': 'newuser',
            'password': password,
            'password_confirm': password,
        })
        
        assert response.status_code == 201
        
        # Récupérer l'user depuis la DB
        user = User.objects.get(email='newuser@example.com')
        
        # Vérifier que le mot de passe est hashé
        assert user.password != password
        assert user.password.startswith('pbkdf2_sha256$') or user.password.startswith('argon2')


@pytest.mark.django_db
class TestLogin:
    """Tests pour l'endpoint POST /auth/login/"""

    def test_login_with_valid_credentials(self, api_client, authenticated_user):
        """Login avec credentials valides doit succéder"""
        response = api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',  # Le mot de passe du fixture
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'success'
        assert data['user']['email'] == authenticated_user.email
        
        # Vérifier que la session a été créée
        assert '_auth_user_id' in api_client.session

    def test_login_with_invalid_password(self, api_client, authenticated_user):
        """Login avec password invalide doit échouer"""
        response = api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'WrongPassword123!',
        })
        
        assert response.status_code == 401
        data = response.json()
        assert data['status'] == 'error'

    def test_login_with_nonexistent_email(self, api_client):
        """Login avec email inexistant doit échouer"""
        response = api_client.post('/auth/login/', {
            'email': 'nonexistent@example.com',
            'password': 'SecurePassword123!',
        })
        
        assert response.status_code == 401
        data = response.json()
        assert data['status'] == 'error'

    def test_login_with_missing_email(self, api_client):
        """Login sans email doit échouer"""
        response = api_client.post('/auth/login/', {
            'password': 'SecurePassword123!',
        })
        
        assert response.status_code == 400
        data = response.json()
        assert data['status'] == 'error'

    def test_login_with_missing_password(self, api_client):
        """Login sans password doit échouer"""
        response = api_client.post('/auth/login/', {
            'email': 'test@example.com',
        })
        
        assert response.status_code == 400
        data = response.json()
        assert data['status'] == 'error'

    def test_login_increments_failed_attempts_on_wrong_password(self, api_client, authenticated_user):
        """Échec login doit incrémenter failed_login_attempts"""
        # Avant : 0 tentatives échouées
        user = User.objects.get(id=authenticated_user.id)
        assert user.failed_login_attempts == 0
        
        # Tentative 1 : mauvais password
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'WrongPassword1!',
        })
        user.refresh_from_db()
        assert user.failed_login_attempts == 1
        
        # Tentative 2
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'WrongPassword2!',
        })
        user.refresh_from_db()
        assert user.failed_login_attempts == 2

    def test_login_locks_account_after_5_failed_attempts(self, api_client, authenticated_user):
        """Après 5 tentatives échouées, le compte doit être verrouillé"""
        for i in range(5):
            api_client.post('/auth/login/', {
                'email': authenticated_user.email,
                'password': f'WrongPassword{i}!',
            })
        
        user = User.objects.get(id=authenticated_user.id)
        assert user.account_locked is True
        assert user.locked_until is not None

    def test_login_fails_when_account_locked(self, api_client, authenticated_user):
        """Login doit échouer si le compte est verrouillé"""
        # Verrouiller manuellement le compte
        authenticated_user.account_locked = True
        authenticated_user.save()
        
        response = api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',  # Correct password
        })
        
        assert response.status_code == 403
        data = response.json()
        assert data['status'] == 'error'
        assert 'locked' in data['message'].lower()

    def test_login_resets_failed_attempts_on_success(self, api_client, authenticated_user):
        """Login réussi doit réinitialiser failed_login_attempts"""
        # Incrémenter manuellement les tentatives
        authenticated_user.failed_login_attempts = 3
        authenticated_user.save()
        
        # Login réussi
        response = api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        assert response.status_code == 200
        user = User.objects.get(id=authenticated_user.id)
        assert user.failed_login_attempts == 0


@pytest.mark.django_db
class TestLogout:
    """Tests pour l'endpoint POST /auth/logout/"""

    def test_logout_when_authenticated(self, api_client, authenticated_user):
        """Logout d'un utilisateur authentifié doit succéder"""
        # D'abord login
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        # Puis logout
        response = api_client.post('/auth/logout/')
        
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'success'
        
        # Vérifier que la session a été détruite
        assert '_auth_user_id' not in api_client.session

    def test_logout_when_not_authenticated(self, api_client):
        """Logout sans authentification doit retourner une réponse (idempotent)"""
        response = api_client.post('/auth/logout/')
        
        # Logout est idempotent : même si pas connecté, on retourne succès
        assert response.status_code in [200, 401]
        data = response.json()
        # Doit avoir un 'status' dans la réponse
        assert 'status' in data


@pytest.mark.django_db
class TestMe:
    """Tests pour l'endpoint GET /auth/me/"""

    def test_me_when_authenticated(self, api_client, authenticated_user):
        """GET /auth/me/ d'un utilisateur authentifié doit retourner ses infos"""
        # D'abord login
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        # Puis GET /auth/me/
        response = api_client.get('/auth/me/')
        
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'success'
        assert data['user']['id'] == authenticated_user.id
        assert data['user']['username'] == authenticated_user.username
        assert data['user']['email'] == authenticated_user.email

    def test_me_when_not_authenticated(self, api_client):
        """GET /auth/me/ sans authentification doit échouer"""
        response = api_client.get('/auth/me/')
        
        assert response.status_code == 401
        data = response.json()
        assert data['status'] == 'error'

    def test_me_has_required_fields(self, api_client, authenticated_user):
        """GET /auth/me/ doit retourner tous les champs requis"""
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        response = api_client.get('/auth/me/')
        data = response.json()
        user_data = data['user']
        
        required_fields = ['id', 'username', 'email', 'is_staff', 'is_superuser', 'date_joined']
        for field in required_fields:
            assert field in user_data


@pytest.mark.django_db
class TestSecurityHeaders:
    """Tests pour les en-têtes de sécurité sur endpoints auth"""

    def test_auth_endpoints_have_security_headers(self, api_client):
        """Les endpoints auth doivent avoir les en-têtes de sécurité"""
        response = api_client.get('/auth/me/')
        
        assert 'X-Frame-Options' in response
        assert 'X-Content-Type-Options' in response
        assert 'Referrer-Policy' in response
