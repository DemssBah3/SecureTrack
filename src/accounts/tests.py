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

@pytest.mark.django_db
class TestSetup2FA:
    """Tests pour l'endpoint POST /auth/2fa/setup/"""

    def test_setup_2fa_when_not_authenticated(self, api_client):
        """Setup 2FA sans authentification doit échouer"""
        response = api_client.post('/auth/2fa/setup/')
        
        assert response.status_code == 401
        data = response.json()
        assert data['status'] == 'error'

    def test_setup_2fa_when_authenticated(self, api_client, authenticated_user):
        """Setup 2FA pour utilisateur authentifié doit succéder"""
        # D'abord login
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        # Puis setup 2FA
        response = api_client.post('/auth/2fa/setup/')
        
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'success'
        assert 'data' in data
        assert 'secret' in data['data']
        assert 'qr_code' in data['data']
        assert 'backup_codes' in data['data']
        
        # Les backup codes doivent être 10
        assert len(data['data']['backup_codes']) == 10

    def test_setup_2fa_generates_valid_secret(self, api_client, authenticated_user):
        """Le secret TOTP doit être valide (base32)"""
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        response = api_client.post('/auth/2fa/setup/')
        data = response.json()
        secret = data['data']['secret']
        
        # Secret doit être base32 (32 caractères alphanumériques + =)
        assert len(secret) == 32
        assert all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' for c in secret)

    def test_setup_2fa_generates_qr_code(self, api_client, authenticated_user):
        """Le QR code doit être en base64"""
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        response = api_client.post('/auth/2fa/setup/')
        data = response.json()
        qr_code = data['data']['qr_code']
        
        # QR code doit être en base64 (PNG)
        assert qr_code.startswith('data:image/png;base64,')
        assert len(qr_code) > 100  # Au moins quelques caractères de données

    def test_setup_2fa_stores_secret_in_session(self, api_client, authenticated_user):
        """Le secret doit être stocké temporairement en session"""
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        response = api_client.post('/auth/2fa/setup/')
        
        # Vérifier que la session contient le secret temporaire
        assert 'temp_totp_secret' in api_client.session
        assert 'temp_backup_codes' in api_client.session

    def test_setup_2fa_when_already_enabled(self, api_client, authenticated_user):
        """Setup 2FA quand déjà activé doit échouer"""
        # Activer 2FA manuellement
        authenticated_user.totp_enabled = True
        authenticated_user.totp_secret = 'JBSWY3DPEBLW64TMMQ======'
        authenticated_user.save()
        
        # Login
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        # Essayer setup 2FA
        response = api_client.post('/auth/2fa/setup/')
        
        assert response.status_code == 400
        data = response.json()
        assert data['status'] == 'error'
        assert 'already enabled' in data['message'].lower()

    def test_backup_codes_format(self, api_client, authenticated_user):
        """Les codes de secours doivent être au format XXXX-XXXX-XXXX"""
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        response = api_client.post('/auth/2fa/setup/')
        data = response.json()
        backup_codes = data['data']['backup_codes']
        
        # Chaque code doit être au format XXXX-XXXX-XXXX
        for code in backup_codes:
            parts = code.split('-')
            assert len(parts) == 3
            assert len(parts[0]) == 4
            assert len(parts[1]) == 4
            assert len(parts[2]) == 4


@pytest.mark.django_db
class TestVerify2FA:
    """Tests pour l'endpoint POST /auth/2fa/verify/"""

    def test_verify_2fa_when_not_authenticated(self, api_client):
        """Vérifier 2FA sans authentification doit échouer"""
        response = api_client.post('/auth/2fa/verify/', {'code': '000000'})
        
        assert response.status_code == 401
        data = response.json()
        assert data['status'] == 'error'

    def test_verify_2fa_without_setup(self, api_client, authenticated_user):
        """Vérifier 2FA sans faire setup d'abord doit échouer"""
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        response = api_client.post('/auth/2fa/verify/', {'code': '000000'})
        
        assert response.status_code == 400
        data = response.json()
        assert data['status'] == 'error'
        assert 'setup' in data['message'].lower()

    def test_verify_2fa_with_invalid_code_format(self, api_client, authenticated_user):
        """Vérifier 2FA avec code invalide doit échouer"""
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        # Setup 2FA
        api_client.post('/auth/2fa/setup/')
        
        # Vérifier avec code invalide (trop court)
        response = api_client.post('/auth/2fa/verify/', {'code': '123'})
        
        assert response.status_code == 400
        data = response.json()
        assert data['status'] == 'error'
        assert 'invalid' in data['message'].lower()

    def test_verify_2fa_with_wrong_code(self, api_client, authenticated_user):
        """Vérifier 2FA avec code incorrect doit échouer"""
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        # Setup 2FA
        api_client.post('/auth/2fa/setup/')
        
        # Vérifier avec code incorrect
        response = api_client.post('/auth/2fa/verify/', {'code': '000000'})
        
        assert response.status_code == 401
        data = response.json()
        assert data['status'] == 'error'
        assert 'invalid' in data['message'].lower()

    def test_verify_2fa_with_valid_code(self, api_client, authenticated_user):
        """Vérifier 2FA avec code correct doit activer 2FA"""
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        # Setup 2FA
        setup_response = api_client.post('/auth/2fa/setup/')
        setup_data = setup_response.json()
        secret = setup_data['data']['secret']
        
        # Générer un code TOTP valide
        import pyotp
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        
        # Vérifier avec code correct
        response = api_client.post('/auth/2fa/verify/', {'code': valid_code})
        
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'success'
        assert 'enabled successfully' in data['message'].lower()
        
        # Vérifier que 2FA est activé en DB
        user = User.objects.get(id=authenticated_user.id)
        assert user.totp_enabled is True
        assert user.totp_secret == secret

    def test_verify_2fa_returns_backup_codes(self, api_client, authenticated_user):
        """Vérifier 2FA doit retourner les codes de secours"""
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        setup_response = api_client.post('/auth/2fa/setup/')
        setup_data = setup_response.json()
        secret = setup_data['data']['secret']
        backup_codes_setup = setup_data['data']['backup_codes']
        
        import pyotp
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        
        response = api_client.post('/auth/2fa/verify/', {'code': valid_code})
        data = response.json()
        
        # Les codes retournés doivent être les mêmes que ceux du setup
        assert 'backup_codes' in data['data']
        assert data['data']['backup_codes'] == backup_codes_setup

    def test_verify_2fa_cleans_session(self, api_client, authenticated_user):
        """Vérifier 2FA doit nettoyer la session"""
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        setup_response = api_client.post('/auth/2fa/setup/')
        setup_data = setup_response.json()
        secret = setup_data['data']['secret']
        
        # Vérifier que les clés de session existent
        assert 'temp_totp_secret' in api_client.session
        
        import pyotp
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        
        api_client.post('/auth/2fa/verify/', {'code': valid_code})
        
        # Les clés doivent être nettoyées
        assert 'temp_totp_secret' not in api_client.session
        assert 'temp_backup_codes' not in api_client.session


@pytest.mark.django_db
class TestDisable2FA:
    """Tests pour l'endpoint POST /auth/2fa/disable/"""

    def test_disable_2fa_when_not_authenticated(self, api_client):
        """Désactiver 2FA sans authentification doit échouer"""
        response = api_client.post('/auth/2fa/disable/', {'password': 'test'})
        
        assert response.status_code == 401
        data = response.json()
        assert data['status'] == 'error'

    def test_disable_2fa_when_not_enabled(self, api_client, authenticated_user):
        """Désactiver 2FA quand pas activé doit échouer"""
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        response = api_client.post('/auth/2fa/disable/', {'password': 'TestPassword123!'})
        
        assert response.status_code == 400
        data = response.json()
        assert data['status'] == 'error'
        assert 'not enabled' in data['message'].lower()

    def test_disable_2fa_without_password(self, api_client, authenticated_user):
        """Désactiver 2FA sans mot de passe doit échouer"""
        # Activer 2FA
        authenticated_user.totp_enabled = True
        authenticated_user.totp_secret = 'JBSWY3DPEBLW64TMMQ======'
        authenticated_user.save()
        
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        response = api_client.post('/auth/2fa/disable/', {})
        
        assert response.status_code == 400
        data = response.json()
        assert data['status'] == 'error'
        assert 'password' in data['message'].lower()

    def test_disable_2fa_with_wrong_password(self, api_client, authenticated_user):
        """Désactiver 2FA avec mauvais mot de passe doit échouer"""
        authenticated_user.totp_enabled = True
        authenticated_user.totp_secret = 'JBSWY3DPEBLW64TMMQ======'
        authenticated_user.save()
        
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        response = api_client.post('/auth/2fa/disable/', {'password': 'WrongPassword123!'})
        
        assert response.status_code == 401
        data = response.json()
        assert data['status'] == 'error'

    def test_disable_2fa_with_correct_password(self, api_client, authenticated_user):
        """Désactiver 2FA avec bon mot de passe doit succéder"""
        authenticated_user.totp_enabled = True
        authenticated_user.totp_secret = 'JBSWY3DPEBLW64TMMQ======'
        authenticated_user.save()
        
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        response = api_client.post('/auth/2fa/disable/', {'password': 'TestPassword123!'})
        
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'success'
        
        # Vérifier que 2FA est désactivé en DB
        user = User.objects.get(id=authenticated_user.id)
        assert user.totp_enabled is False
        assert user.totp_secret == ''


@pytest.mark.django_db
class TestLoginWith2FA:
    """Tests pour le login avec 2FA"""

    def test_login_with_2fa_enabled_requires_totp(self, api_client, authenticated_user):
        """Login avec 2FA activé doit demander le code TOTP"""
        # Activer 2FA
        import pyotp
        secret = pyotp.random_base32()
        authenticated_user.totp_enabled = True
        authenticated_user.totp_secret = secret
        authenticated_user.save()
        
        # Login
        response = api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'success'
        assert 'requires_2fa' in data['data']
        assert data['data']['requires_2fa'] is True

    def test_verify_totp_login_with_valid_code(self, api_client, authenticated_user):
        """Vérifier TOTP au login avec code valide doit créer session"""
        import pyotp
        secret = pyotp.random_base32()
        authenticated_user.totp_enabled = True
        authenticated_user.totp_secret = secret
        authenticated_user.save()
        
        # Login
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        # Générer code TOTP valide
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        
        # Vérifier TOTP
        response = api_client.post('/auth/verify-totp-login/', {'code': valid_code})
        
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'success'
        assert 'user' in data
        
        # Vérifier que la session a été créée
        assert '_auth_user_id' in api_client.session

    def test_verify_totp_login_with_invalid_code(self, api_client, test_user):
        """Vérifier TOTP au login avec code invalide doit échouer"""
        import pyotp
        secret = pyotp.random_base32()
        test_user.totp_enabled = True
        test_user.totp_secret = secret
        test_user.save()

        # Login
        api_client.post('/auth/login/', {
            'email': test_user.email,
            'password': 'TestPassword123!',
        })

        # Vérifier avec code invalide
        response = api_client.post('/auth/verify-totp-login/', {'code': '000000'})

        assert response.status_code == 401
        data = response.json()
        assert data['status'] == 'error'

        # Session ne doit pas être créée
        assert '_auth_user_id' not in api_client.session

    def test_verify_totp_login_without_pending_2fa(self, api_client):
        """Vérifier TOTP sans login 2FA en attente doit échouer"""
        response = api_client.post('/auth/verify-totp-login/', {'code': '123456'})
        
        assert response.status_code == 400
        data = response.json()
        assert data['status'] == 'error'
        assert 'pending' in data['message'].lower()

    def test_verify_totp_login_cleans_session(self, api_client, authenticated_user):
        """Vérifier TOTP doit nettoyer la session"""
        import pyotp
        secret = pyotp.random_base32()
        authenticated_user.totp_enabled = True
        authenticated_user.totp_secret = secret
        authenticated_user.save()
        
        # Login
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        # Vérifier que pending_2fa_user_id existe
        assert 'pending_2fa_user_id' in api_client.session
        
        # Vérifier TOTP
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        api_client.post('/auth/verify-totp-login/', {'code': valid_code})
        
        # pending_2fa_user_id doit être nettoyé
        assert 'pending_2fa_user_id' not in api_client.session


@pytest.mark.django_db
class TestGetBackupCodes:
    """Tests pour l'endpoint GET /auth/backup-codes/"""

    def test_get_backup_codes_when_not_authenticated(self, api_client):
        """Récupérer backup codes sans authentification doit échouer"""
        response = api_client.get('/auth/backup-codes/')
        
        assert response.status_code == 401
        data = response.json()
        assert data['status'] == 'error'

    def test_get_backup_codes_when_2fa_not_enabled(self, api_client, authenticated_user):
        """Récupérer backup codes sans 2FA doit échouer"""
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        response = api_client.get('/auth/backup-codes/')
        
        assert response.status_code == 400
        data = response.json()
        assert data['status'] == 'error'

    def test_get_backup_codes_when_2fa_enabled(self, api_client, authenticated_user):
        """Récupérer backup codes avec 2FA doit succéder"""
        authenticated_user.totp_enabled = True
        authenticated_user.totp_secret = 'JBSWY3DPEBLW64TMMQ======'
        authenticated_user.save()
        
        api_client.post('/auth/login/', {
            'email': authenticated_user.email,
            'password': 'TestPassword123!',
        })
        
        response = api_client.get('/auth/backup-codes/')
        
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'success'
        assert data['data']['2fa_enabled'] is True

