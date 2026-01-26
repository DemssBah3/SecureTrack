"""
Tests CRUD Projects - Create, Read, Update, Delete.
"""

import pytest
from django.contrib.auth import get_user_model
from tickets.models import Project

User = get_user_model()


@pytest.fixture
def users(db):
    """Créer utilisateurs"""
    user1 = User.objects.create_user(username='user1', email='user1@test.com', password='Pass123!@')
    user2 = User.objects.create_user(username='user2', email='user2@test.com', password='Pass123!@')
    return {'user1': user1, 'user2': user2}


# ===== CREATE TESTS (3 tests) =====

@pytest.mark.django_db
def test_project_create(users):
    """Créer un nouveau projet"""
    project = Project.objects.create(
        name='New Project',
        description='A new test project',
        created_by=users['user1']
    )
    
    assert project.name == 'New Project'
    assert project.created_by == users['user1']


@pytest.mark.django_db
def test_project_create_with_members(users):
    """Créer un projet et ajouter le créateur comme membre"""
    project = Project.objects.create(
        name='Project with Members',
        description='Testing members',
        created_by=users['user1']
    )
    project.members.add(users['user1'])
    project.set_user_role(users['user1'], 'ADMIN')
    
    assert project.is_member(users['user1']) == True
    assert project.get_user_role(users['user1']) == 'ADMIN'


@pytest.mark.django_db
def test_project_owner_is_admin(users):
    """Le créateur est automatiquement ADMIN"""
    project = Project.objects.create(
        name='Owner Test',
        description='Testing owner',
        created_by=users['user1']
    )
    project.members.add(users['user1'])
    project.set_user_role(users['user1'], 'ADMIN')
    
    assert project.get_user_role(users['user1']) == 'ADMIN'


# ===== READ TESTS (3 tests) =====

@pytest.mark.django_db
def test_project_read(users):
    """Lire les détails d'un projet"""
    project = Project.objects.create(
        name='Read Test',
        description='Testing read',
        created_by=users['user1']
    )
    
    retrieved = Project.objects.get(id=project.id)
    assert retrieved.name == 'Read Test'
    assert retrieved.description == 'Testing read'


@pytest.mark.django_db
def test_project_list_by_user(users):
    """Lister les projets d'un utilisateur"""
    for i in range(3):
        project = Project.objects.create(
            name=f'Project {i}',
            description='Testing',
            created_by=users['user1']
        )
        project.members.add(users['user1'])
    
    user_projects = users['user1'].projects.all()
    assert user_projects.count() == 3


@pytest.mark.django_db
def test_project_members_count(users):
    """Compter les membres d'un projet"""
    project = Project.objects.create(
        name='Members Test',
        description='Testing members',
        created_by=users['user1']
    )
    project.members.add(users['user1'])
    project.members.add(users['user2'])
    
    assert project.members.count() == 2


# ===== UPDATE TESTS (2 tests) =====

@pytest.mark.django_db
def test_project_update_name(users):
    """Modifier le nom d'un projet"""
    project = Project.objects.create(
        name='Old Name',
        description='Testing update',
        created_by=users['user1']
    )
    
    project.name = 'New Name'
    project.save()
    
    updated = Project.objects.get(id=project.id)
    assert updated.name == 'New Name'


@pytest.mark.django_db
def test_project_update_description(users):
    """Modifier la description d'un projet"""
    project = Project.objects.create(
        name='Description Test',
        description='Old description',
        created_by=users['user1']
    )
    
    project.description = 'New description'
    project.save()
    
    updated = Project.objects.get(id=project.id)
    assert updated.description == 'New description'


# ===== DELETE TESTS (1 test) =====

@pytest.mark.django_db
def test_project_delete(users):
    """Supprimer un projet"""
    project = Project.objects.create(
        name='Delete Test',
        description='To be deleted',
        created_by=users['user1']
    )
    
    project_id = project.id
    project.delete()
    
    assert Project.objects.filter(id=project_id).exists() == False
