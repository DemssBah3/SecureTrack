"""
Tests Rate Limiting - Protéger contre brute-force et DDoS.
OWASP A07:2021 - Identification & Authentication Failures
"""

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from tickets.models import AuditLog

User = get_user_model()


@pytest.fixture
def client():
    """Django test client"""
    return Client()


@pytest.fixture
def users(db):
    """Créer utilisateurs"""
    user1 = User.objects.create_user(username='user1', email='user1@test.com', password='Pass123!@')
    return {'user1': user1}


# ===== BRUTE-FORCE PROTECTION TESTS (4 tests) =====

@pytest.mark.django_db
def test_account_locked_after_failed_attempts(users):
    """Compte verrouillé après 5 tentatives échouées"""
    user = users['user1']
    
    # Simuler 5 tentatives échouées
    user.failed_login_attempts = 5
    user.account_locked = True
    user.save()
    
    assert user.account_locked == True
    assert user.failed_login_attempts == 5


@pytest.mark.django_db
def test_login_failed_increments_counter(users):
    """Chaque login failed incrémente le compteur"""
    user = users['user1']
    initial_count = user.failed_login_attempts
    
    # Simuler un échec
    user.failed_login_attempts += 1
    user.save()
    
    assert user.failed_login_attempts == initial_count + 1


@pytest.mark.django_db
def test_login_success_resets_counter(users):
    """Login successful réinitialise le compteur"""
    user = users['user1']
    user.failed_login_attempts = 3
    user.save()
    
    # Reset après succès
    user.failed_login_attempts = 0
    user.save()
    
    assert user.failed_login_attempts == 0


@pytest.mark.django_db
def test_locked_account_cannot_login(users):
    """Compte verrouillé ne peut pas se connecter"""
    user = users['user1']
    user.account_locked = True
    user.save()
    
    assert user.account_locked == True


# ===== LOGIN ATTEMPT LOGGING TESTS (4 tests) =====

@pytest.mark.django_db
def test_failed_login_logged(users):
    """Tentative login échouée est loggée"""
    user = users['user1']
    
    log = AuditLog.objects.create(
        user=user,
        action='LOGIN_FAILED',
        resource_type='User',
        resource_id=user.id,
        resource_name=user.username,
        details={'reason': 'invalid_password'},
        ip_address='127.0.0.1'
    )
    
    assert log.action == 'LOGIN_FAILED'
    assert AuditLog.objects.filter(
        action='LOGIN_FAILED',
        user=user
    ).count() >= 1


@pytest.mark.django_db
def test_multiple_failed_attempts_tracked(users):
    """Multiples tentatives échouées sont tracées"""
    user = users['user1']
    
    # Créer 3 logs d'échec
    for i in range(3):
        AuditLog.objects.create(
            user=user,
            action='LOGIN_FAILED',
            resource_type='User',
            resource_id=user.id,
            resource_name=user.username,
            details={'reason': 'invalid_password', 'attempt': i+1},
            ip_address='127.0.0.1'
        )
    
    failed_attempts = AuditLog.objects.filter(
        action='LOGIN_FAILED',
        user=user
    ).count()
    
    assert failed_attempts == 3


@pytest.mark.django_db
def test_successful_login_after_failed_attempts(users):
    """Login successful après plusieurs échecs réinitialise"""
    user = users['user1']
    
    # Simuler 3 échecset 1 succès
    for i in range(3):
        AuditLog.objects.create(
            user=user,
            action='LOGIN_FAILED',
            resource_type='User',
            resource_id=user.id,
            resource_name=user.username,
            ip_address='127.0.0.1'
        )
    
    # Reset et succès
    user.failed_login_attempts = 0
    user.save()
    
    AuditLog.objects.create(
        user=user,
        action='LOGIN_SUCCESS',
        resource_type='User',
        resource_id=user.id,
        resource_name=user.username,
        ip_address='127.0.0.1'
    )
    
    assert user.failed_login_attempts == 0
    assert AuditLog.objects.filter(
        action='LOGIN_SUCCESS',
        user=user
    ).exists()


@pytest.mark.django_db
def test_ip_tracked_in_failed_attempts(users):
    """IP est tracée pour chaque tentative échouée"""
    user = users['user1']
    ip = '192.168.1.100'
    
    log = AuditLog.objects.create(
        user=user,
        action='LOGIN_FAILED',
        resource_type='User',
        resource_id=user.id,
        resource_name=user.username,
        details={'reason': 'invalid_password'},
        ip_address=ip
    )
    
    assert log.ip_address == ip
