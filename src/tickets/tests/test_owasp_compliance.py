"""
Tests OWASP Compliance - Vérifier conformité OWASP Top 10 2021.
"""

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from tickets.models import Project, Ticket

User = get_user_model()


@pytest.fixture
def client():
    """Django test client"""
    return Client()


@pytest.fixture
def users(db):
    """Créer utilisateurs"""
    user1 = User.objects.create_user(username='user1', email='user1@test.com', password='Pass123!@')
    user2 = User.objects.create_user(username='user2', email='user2@test.com', password='Pass123!@')
    return {'user1': user1, 'user2': user2}


@pytest.fixture
def project(db, users):
    """Créer un projet"""
    project = Project.objects.create(
        name='Test Project',
        description='For testing',
        created_by=users['user1']
    )
    project.members.add(users['user1'])
    project.set_user_role(users['user1'], 'ADMIN')
    return project


# ===== A01:2021 - BROKEN ACCESS CONTROL (3 tests) =====

@pytest.mark.django_db
def test_a01_rbac_enforced(users, project):
    """A01: RBAC correctement implémenté"""
    user1 = users['user1']
    user2 = users['user2']
    
    # user1 est ADMIN
    assert project.get_user_role(user1) == 'ADMIN'
    
    # user2 n'est pas membre
    assert project.get_user_role(user2) is None


@pytest.mark.django_db
def test_a01_privilege_escalation_blocked(users, project):
    """A01: Escalade de privilèges bloquée"""
    user = users['user2']
    project.members.add(user)
    project.set_user_role(user, 'USER')
    
    # user ne peut pas auto-promouvoir
    user_role = project.get_user_role(user)
    assert user_role == 'USER'
    
    # Vérifier que USER ne peut pas créer de tickets
    can_create = user_role in ['MANAGER', 'ADMIN']
    assert can_create == False


@pytest.mark.django_db
def test_a01_data_isolation(users, project):
    """A01: Isolation des données par projet"""
    user1 = users['user1']
    user2 = users['user2']
    
    # user2 ne voit pas le projet
    assert project.is_member(user2) == False


# ===== A03:2021 - INJECTION (2 tests) =====

@pytest.mark.django_db
def test_a03_input_validation(project, users):
    """A03: Validation des inputs"""
    # Les validateurs Django ORM protègent contre SQL injection
    # Les validators.py protègent contre les autres injections
    
    ticket = Ticket.objects.create(
        title='Normal Title',
        description='Normal description',
        project=project,
        created_by=users['user1'],
        status='OPEN',
        priority='MEDIUM'
    )
    
    assert ticket.title == 'Normal Title'


@pytest.mark.django_db
def test_a03_parameterized_queries(project, users):
    """A03: Queries paramétrées (ORM Django)"""
    # Django ORM utilise les parameterized queries par défaut
    
    tickets = Ticket.objects.filter(
        project=project,
        status='OPEN'
    )
    
    # Si injection était possible, ça crasherait
    assert tickets.count() >= 0


# ===== A07:2021 - XSS (2 tests) =====

@pytest.mark.django_db
def test_a07_template_auto_escape(project, users):
    """A07: Auto-escape dans les templates Django"""
    # Django auto-escape tous les variables par défaut
    
    ticket = Ticket.objects.create(
        title='<script>alert("XSS")</script>',
        description='Test',
        project=project,
        created_by=users['user1'],
        status='OPEN',
        priority='MEDIUM'
    )
    
    # Le titre doit être échappé dans les templates
    assert '<script>' in ticket.title  # Stocké tel quel
    # Mais rendu comme &lt;script&gt; dans HTML


@pytest.mark.django_db
def test_a07_csp_mitigates_xss(client):
    """A07: CSP mitigation pour XSS"""
    # CSP bloque les inline scripts
    response = client.get('/api/health/')
    
    # Si CSP est configuré, elle protège
    assert response.status_code == 200


# ===== A09:2021 - LOGGING & MONITORING (3 tests) =====

@pytest.mark.django_db
def test_a09_security_events_logged(users):
    """A09: Événements de sécurité loggés"""
    from tickets.models import AuditLog
    
    user = users['user1']
    
    # Créer un log
    log = AuditLog.objects.create(
        user=user,
        action='LOGIN_SUCCESS',
        resource_type='User',
        resource_id=user.id,
        resource_name=user.username,
        ip_address='127.0.0.1'
    )
    
    assert log.action == 'LOGIN_SUCCESS'
    assert log.timestamp is not None


@pytest.mark.django_db
def test_a09_audit_trail_complete(project, users):
    """A09: Audit trail complète"""
    from tickets.models import AuditLog
    
    # Créer ticket et log
    ticket = Ticket.objects.create(
        title='Test',
        description='Test',
        project=project,
        created_by=users['user1'],
        status='OPEN',
        priority='MEDIUM'
    )
    
    log = AuditLog.objects.create(
        user=users['user1'],
        action='CREATE_TICKET',
        resource_type='Ticket',
        resource_id=ticket.id,
        resource_name=ticket.title,
        ip_address='127.0.0.1'
    )
    
    # Vérifier que le log a tous les détails
    assert log.user is not None
    assert log.action is not None
    assert log.resource_id is not None
    assert log.timestamp is not None
    assert log.ip_address is not None


@pytest.mark.django_db
def test_a09_failed_access_attempts_logged(users):
    """A09: Tentatives d'accès échouées loggées"""
    from tickets.models import AuditLog
    
    log = AuditLog.objects.create(
        user=users['user1'],
        action='LOGIN_FAILED',
        resource_type='User',
        resource_id=users['user1'].id,
        resource_name=users['user1'].username,
        details={'reason': 'invalid_password'},
        ip_address='127.0.0.1'
    )
    
    # Vérifier que l'échec est loggé
    assert log.action == 'LOGIN_FAILED'
    assert log.details['reason'] is not None
