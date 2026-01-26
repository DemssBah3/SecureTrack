"""
Tests CRUD Tickets - Create, Read, Update, Delete.
"""

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse
from tickets.models import Project, Ticket, ProjectMember

User = get_user_model()


@pytest.fixture
def users(db):
    """Créer utilisateurs"""
    user1 = User.objects.create_user(username='user1', email='user1@test.com', password='Pass123!@')
    user2 = User.objects.create_user(username='user2', email='user2@test.com', password='Pass123!@')
    user3 = User.objects.create_user(username='user3', email='user3@test.com', password='Pass123!@')
    return {'user1': user1, 'user2': user2, 'user3': user3}


@pytest.fixture
def project(db, users):
    """Créer un projet avec members"""
    project = Project.objects.create(
        name='Test Project',
        description='For testing',
        created_by=users['user1']
    )
    project.members.add(users['user1'])
    project.set_user_role(users['user1'], 'ADMIN')
    
    project.members.add(users['user2'])
    project.set_user_role(users['user2'], 'MANAGER')
    
    project.members.add(users['user3'])
    project.set_user_role(users['user3'], 'USER')
    
    return project


# ===== CREATE TESTS (4 tests) =====

@pytest.mark.django_db
def test_ticket_create_manager(project, users):
    """MANAGER peut créer un ticket"""
    ticket = Ticket.objects.create(
        title='Test Ticket',
        description='A test ticket',
        project=project,
        created_by=users['user2'],
        status='OPEN',
        priority='MEDIUM'
    )
    
    assert ticket.title == 'Test Ticket'
    assert ticket.created_by == users['user2']
    assert ticket.status == 'OPEN'


@pytest.mark.django_db
def test_ticket_create_admin(project, users):
    """ADMIN peut créer un ticket"""
    ticket = Ticket.objects.create(
        title='Admin Ticket',
        description='Created by admin',
        project=project,
        created_by=users['user1'],
        status='OPEN',
        priority='HIGH'
    )
    
    assert ticket.created_by == users['user1']
    assert ticket.priority == 'HIGH'


@pytest.mark.django_db
def test_ticket_create_with_assignment(project, users):
    """Créer un ticket avec assignation"""
    ticket = Ticket.objects.create(
        title='Assigned Ticket',
        description='Assigned to user2',
        project=project,
        created_by=users['user1'],
        assigned_to=users['user2'],
        status='OPEN',
        priority='MEDIUM'
    )
    
    assert ticket.assigned_to == users['user2']


@pytest.mark.django_db
def test_ticket_create_validates_status(project, users):
    """Créer un ticket avec statut valide"""
    valid_statuses = ['OPEN', 'IN_PROGRESS', 'CLOSED']
    
    for status in valid_statuses:
        ticket = Ticket.objects.create(
            title=f'Ticket {status}',
            description='Testing status',
            project=project,
            created_by=users['user1'],
            status=status,
            priority='MEDIUM'
        )
        assert ticket.status == status


# ===== READ TESTS (4 tests) =====

@pytest.mark.django_db
def test_ticket_detail_read(project, users):
    """Lire les détails d'un ticket"""
    ticket = Ticket.objects.create(
        title='Read Test',
        description='Test reading',
        project=project,
        created_by=users['user1'],
        status='OPEN',
        priority='MEDIUM'
    )
    
    retrieved = Ticket.objects.get(id=ticket.id)
    assert retrieved.title == 'Read Test'
    assert retrieved.description == 'Test reading'


@pytest.mark.django_db
def test_ticket_list_by_project(project, users):
    """Lister les tickets d'un projet"""
    # Créer plusieurs tickets
    for i in range(3):
        Ticket.objects.create(
            title=f'Ticket {i}',
            description='Testing',
            project=project,
            created_by=users['user1'],
            status='OPEN',
            priority='MEDIUM'
        )
    
    tickets = Ticket.objects.filter(project=project)
    assert tickets.count() == 3


@pytest.mark.django_db
def test_ticket_filter_by_status(project, users):
    """Filtrer les tickets par statut"""
    Ticket.objects.create(
        title='Open Ticket',
        description='Testing',
        project=project,
        created_by=users['user1'],
        status='OPEN',
        priority='MEDIUM'
    )
    Ticket.objects.create(
        title='Closed Ticket',
        description='Testing',
        project=project,
        created_by=users['user1'],
        status='CLOSED',
        priority='MEDIUM'
    )
    
    open_tickets = Ticket.objects.filter(project=project, status='OPEN')
    closed_tickets = Ticket.objects.filter(project=project, status='CLOSED')
    
    assert open_tickets.count() == 1
    assert closed_tickets.count() == 1


@pytest.mark.django_db
def test_ticket_filter_by_priority(project, users):
    """Filtrer les tickets par priorité"""
    for priority in ['LOW', 'MEDIUM', 'HIGH']:
        Ticket.objects.create(
            title=f'Ticket {priority}',
            description='Testing',
            project=project,
            created_by=users['user1'],
            status='OPEN',
            priority=priority
        )
    
    high_priority = Ticket.objects.filter(project=project, priority='HIGH')
    assert high_priority.count() == 1


# ===== UPDATE TESTS (4 tests) =====

@pytest.mark.django_db
def test_ticket_update_status(project, users):
    """Modifier le statut d'un ticket"""
    ticket = Ticket.objects.create(
        title='Update Test',
        description='Testing update',
        project=project,
        created_by=users['user1'],
        status='OPEN',
        priority='MEDIUM'
    )
    
    ticket.status = 'IN_PROGRESS'
    ticket.save()
    
    updated = Ticket.objects.get(id=ticket.id)
    assert updated.status == 'IN_PROGRESS'


@pytest.mark.django_db
def test_ticket_update_priority(project, users):
    """Modifier la priorité d'un ticket"""
    ticket = Ticket.objects.create(
        title='Priority Test',
        description='Testing priority',
        project=project,
        created_by=users['user1'],
        status='OPEN',
        priority='LOW'
    )
    
    ticket.priority = 'HIGH'
    ticket.save()
    
    updated = Ticket.objects.get(id=ticket.id)
    assert updated.priority == 'HIGH'


@pytest.mark.django_db
def test_ticket_update_assignment(project, users):
    """Réassigner un ticket"""
    ticket = Ticket.objects.create(
        title='Assignment Test',
        description='Testing assignment',
        project=project,
        created_by=users['user1'],
        assigned_to=users['user2'],
        status='OPEN',
        priority='MEDIUM'
    )
    
    ticket.assigned_to = users['user3']
    ticket.save()
    
    updated = Ticket.objects.get(id=ticket.id)
    assert updated.assigned_to == users['user3']


@pytest.mark.django_db
def test_ticket_update_description(project, users):
    """Modifier la description d'un ticket"""
    ticket = Ticket.objects.create(
        title='Desc Test',
        description='Original description',
        project=project,
        created_by=users['user1'],
        status='OPEN',
        priority='MEDIUM'
    )
    
    ticket.description = 'Updated description'
    ticket.save()
    
    updated = Ticket.objects.get(id=ticket.id)
    assert updated.description == 'Updated description'


# ===== DELETE TESTS (2 tests) =====

@pytest.mark.django_db
def test_ticket_delete(project, users):
    """Supprimer un ticket"""
    ticket = Ticket.objects.create(
        title='Delete Test',
        description='To be deleted',
        project=project,
        created_by=users['user1'],
        status='OPEN',
        priority='MEDIUM'
    )
    
    ticket_id = ticket.id
    ticket.delete()
    
    assert Ticket.objects.filter(id=ticket_id).exists() == False


@pytest.mark.django_db
def test_ticket_delete_cascade(project, users):
    """Supprimer un ticket supprime ses références"""
    ticket = Ticket.objects.create(
        title='Cascade Test',
        description='Testing cascade',
        project=project,
        created_by=users['user1'],
        assigned_to=users['user2'],
        status='OPEN',
        priority='MEDIUM'
    )
    
    ticket_id = ticket.id
    ticket.delete()
    
    # Vérifier que le ticket est supprimé
    remaining = Ticket.objects.filter(id=ticket_id)
    assert remaining.count() == 0
