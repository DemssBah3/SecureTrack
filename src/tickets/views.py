"""
Views pour gestion tickets et projets avec RBAC complet.
Sécurité: OWASP A01:2021 (Broken Access Control) + A03:2021 (Injection)
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from django.core.paginator import Paginator
from django.core.exceptions import ValidationError
from django.http import HttpResponseForbidden

from .models import Project, Ticket, ProjectMember, AuditLog
from .permissions import (
    require_project_role, 
    require_ticket_permission, 
    log_action
)
from .validators import (
    TicketValidator, 
    ProjectValidator, 
    get_client_ip
)

User = get_user_model()


# ===== DASHBOARD =====

@login_required(login_url='accounts:login')
def dashboard(request):
    """
    Display user dashboard with stats et recent tickets.
    
    FIX VULN #3: Stats filtrées par projets de l'utilisateur
    """
    user = request.user
    
    # ✅ CORRIGÉ: Filtrer par projets de l'utilisateur seulement
    user_projects = user.projects.all()
    
    open_tickets = Ticket.objects.filter(
        project__in=user_projects,
        status='OPEN'
    ).count()
    
    in_progress_tickets = Ticket.objects.filter(
        project__in=user_projects,
        status='IN_PROGRESS'
    ).count()
    
    closed_tickets = Ticket.objects.filter(
        project__in=user_projects,
        status='CLOSED'
    ).count()
    
    assigned_to_me = Ticket.objects.filter(
        project__in=user_projects,
        assigned_to=user
    ).count()
    
    # Récents tickets du user (créés ou assignés)
    recent_tickets = Ticket.objects.filter(
        project__in=user_projects
    ).order_by('-created_at')[:5]
    
    projects = user_projects
    
    context = {
        'open_tickets_count': open_tickets,
        'in_progress_tickets_count': in_progress_tickets,
        'closed_tickets_count': closed_tickets,
        'assigned_to_me_count': assigned_to_me,
        'recent_tickets': recent_tickets,
        'projects': projects,
    }
    return render(request, 'tickets/dashboard.html', context)


# ===== TICKETS LIST & DETAIL =====

@login_required(login_url='accounts:login')
def ticket_list(request):
    """
    List tickets avec filtres.
    
    FIX VULN #1: Filtrer par projets de l'utilisateur seulement
    """
    user = request.user
    
    # ✅ CORRIGÉ: Seulement les projets où l'user est membre
    user_projects = user.projects.all()
    tickets = Ticket.objects.filter(project__in=user_projects)
    
    # Filtres
    search = request.GET.get('search', '').strip()
    status = request.GET.get('status', '').strip()
    priority = request.GET.get('priority', '').strip()
    
    if search:
        # ✅ Validation: échapper les caractères spéciaux
        tickets = tickets.filter(title__icontains=search)
    
    if status and status in ['OPEN', 'IN_PROGRESS', 'CLOSED']:
        tickets = tickets.filter(status=status)
    
    if priority and priority in ['LOW', 'MEDIUM', 'HIGH']:
        tickets = tickets.filter(priority=priority)
    
    # Pagination
    paginator = Paginator(tickets, 10)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'tickets': page_obj,
        'page_obj': page_obj,
        'is_paginated': page_obj.has_other_pages(),
        'search': search,
        'status': status,
        'priority': priority,
    }
    return render(request, 'tickets/ticket_list.html', context)


@login_required(login_url='accounts:login')
@require_ticket_permission('view')
def ticket_detail(request, ticket_id, ticket=None):
    """
    Display ticket details.
    
    FIX VULN #2: Vérifier membership + séparation view/edit permissions
    @require_ticket_permission('view') s'en charge
    """
    project = ticket.project
    user_role = project.get_user_role(request.user)
    
    # Vérifier si peut éditer (séparé de la permission view)
    is_creator = ticket.created_by == request.user
    can_edit = is_creator or user_role in ['MANAGER', 'ADMIN']
    can_delete = is_creator or user_role == 'ADMIN'
    
    context = {
        'ticket': ticket,
        'can_edit': can_edit,
        'can_delete': can_delete,
        'user_role': user_role,
    }
    return render(request, 'tickets/ticket_detail.html', context)


# ===== TICKETS CREATE & EDIT =====

@login_required(login_url='accounts:login')
@require_http_methods(["GET", "POST"])
def ticket_create(request):
    """
    Create a new ticket (MANAGER+ only).
    
    FIX VULN #4: Valider status/priority avant save
    """
    user = request.user
    projects = user.projects.all()
    
    if request.method == 'POST':
        title = request.POST.get('title', '').strip()
        description = request.POST.get('description', '').strip()
        project_id = request.POST.get('project', '').strip()
        status = request.POST.get('status', 'OPEN').strip()
        priority = request.POST.get('priority', 'MEDIUM').strip()
        assigned_to_id = request.POST.get('assigned_to', '').strip()
        
        try:
            # ✅ VALIDATIONS
            title = TicketValidator.validate_title(title)
            description = TicketValidator.validate_description(description)
            status = TicketValidator.validate_status(status)
            priority = TicketValidator.validate_priority(priority)
            
            # Vérifier que project_id est fourni et valide
            if not project_id:
                raise ValidationError("Project is required.")
            
            project = get_object_or_404(Project, id=int(project_id))
            
            # ✅ PERMISSION: Vérifier rôle dans le projet
            user_role = project.get_user_role(request.user)
            if user_role not in ['MANAGER', 'ADMIN']:
                messages.error(request, 'You need at least MANAGER role to create tickets.')
                return redirect('tickets:ticket_list')
            
            # Vérifier que l'assigned_to est membre du projet
            assigned_to = None
            if assigned_to_id:
                try:
                    assigned_to_id = int(assigned_to_id)
                    assigned_to = project.members.get(id=assigned_to_id)
                except (ValueError, User.DoesNotExist):
                    messages.warning(request, 'Assigned user not found or invalid.')
            
            # ✅ CRÉER LE TICKET
            ticket = Ticket.objects.create(
                title=title,
                description=description,
                project=project,
                created_by=request.user,
                assigned_to=assigned_to,
                status=status,
                priority=priority,
            )
            
            # ✅ AUDIT LOG
            log_action(
                user=request.user,
                action='CREATE_TICKET',
                resource_type='Ticket',
                resource_id=ticket.id,
                resource_name=ticket.title,
                details={'status': status, 'priority': priority},
                ip_address=get_client_ip(request)
            )
            
            messages.success(request, 'Ticket created successfully!')
            return redirect('tickets:ticket_detail', ticket_id=ticket.id)
        
        except ValidationError as e:
            messages.error(request, f'Validation error: {e.message}')
        except ValueError as e:
            messages.error(request, f'Invalid input: {str(e)}')
        except Exception as e:
            messages.error(request, f'Error creating ticket: {str(e)}')
    
    context = {'projects': projects}
    return render(request, 'tickets/ticket_form.html', context)


@login_required(login_url='accounts:login')
@require_ticket_permission('edit')
@require_http_methods(["GET", "POST"])
def ticket_edit(request, ticket_id, ticket=None):
    """
    Edit ticket (Creator, MANAGER, or ADMIN only).
    
    @require_ticket_permission('edit') gère les vérifications de permission
    """
    project = ticket.project
    
    projects = request.user.projects.all()
    team_members = project.members.all()
    
    if request.method == 'POST':
        title = request.POST.get('title', ticket.title).strip()
        description = request.POST.get('description', ticket.description).strip()
        status = request.POST.get('status', ticket.status).strip()
        priority = request.POST.get('priority', ticket.priority).strip()
        assigned_to_id = request.POST.get('assigned_to', '')
        
        try:
            # ✅ VALIDATIONS
            title = TicketValidator.validate_title(title)
            description = TicketValidator.validate_description(description)
            status = TicketValidator.validate_status(status)
            priority = TicketValidator.validate_priority(priority)
            
            # Tracker les changements pour audit
            changes = {}
            if ticket.title != title:
                changes['title'] = f"{ticket.title} → {title}"
            if ticket.description != description:
                changes['description'] = "Modified"
            if ticket.status != status:
                changes['status'] = f"{ticket.status} → {status}"
            if ticket.priority != priority:
                changes['priority'] = f"{ticket.priority} → {priority}"
            
            # Mettre à jour le ticket
            ticket.title = title
            ticket.description = description
            ticket.status = status
            ticket.priority = priority
            
            if assigned_to_id:
                try:
                    assigned_to_id = int(assigned_to_id)
                    assigned_to = project.members.get(id=assigned_to_id)
                    if ticket.assigned_to != assigned_to:
                        changes['assigned_to'] = f"{ticket.assigned_to} → {assigned_to.username}"
                    ticket.assigned_to = assigned_to
                except (ValueError, User.DoesNotExist):
                    messages.warning(request, 'Assigned user not found.')
            else:
                if ticket.assigned_to:
                    changes['assigned_to'] = f"{ticket.assigned_to.username} → Unassigned"
                ticket.assigned_to = None
            
            ticket.save()
            
            # ✅ AUDIT LOG
            log_action(
                user=request.user,
                action='UPDATE_TICKET',
                resource_type='Ticket',
                resource_id=ticket.id,
                resource_name=ticket.title,
                details=changes,
                ip_address=get_client_ip(request)
            )
            
            messages.success(request, 'Ticket updated successfully!')
            return redirect('tickets:ticket_detail', ticket_id=ticket.id)
        
        except ValidationError as e:
            messages.error(request, f'Validation error: {e.message}')
        except Exception as e:
            messages.error(request, f'Error updating ticket: {str(e)}')
    
    context = {
        'ticket': ticket,
        'projects': projects,
        'team_members': team_members,
    }
    return render(request, 'tickets/ticket_form.html', context)


# ===== TICKETS DELETE =====

@login_required(login_url='accounts:login')
@require_ticket_permission('delete')
@require_http_methods(["POST"])
def ticket_delete(request, ticket_id, ticket=None):
    """
    Delete ticket (Creator or ADMIN only).
    
    FIX VULN #8: POST only (pas de GET deletion)
    """
    ticket_title = ticket.title
    project = ticket.project
    
    # ✅ AUDIT LOG
    log_action(
        user=request.user,
        action='DELETE_TICKET',
        resource_type='Ticket',
        resource_id=ticket.id,
        resource_name=ticket_title,
        details={'status': ticket.status},
        ip_address=get_client_ip(request)
    )
    
    ticket.delete()
    messages.success(request, f'Ticket "{ticket_title}" deleted successfully!')
    return redirect('tickets:ticket_list')


# ===== PROJECTS LIST & DETAIL =====

@login_required(login_url='accounts:login')
def project_list(request):
    """List all projects where user is member."""
    projects = request.user.projects.all()
    return render(request, 'tickets/project_list.html', {'projects': projects})


@login_required(login_url='accounts:login')
def project_detail(request, project_id):
    """
    Display project details.
    Vérifie déjà que l'user est membre.
    """
    project = get_object_or_404(Project, id=project_id)
    
    # ✅ VÉRIFIER MEMBERSHIP
    if not project.is_member(request.user):
        messages.error(request, 'You do not have access to this project.')
        return redirect('tickets:project_list')
    
    user_role = project.get_user_role(request.user)
    can_manage = user_role in ['MANAGER', 'ADMIN']
    
    context = {
        'project': project,
        'user_role': user_role,
        'can_manage': can_manage,
    }
    return render(request, 'tickets/project_detail.html', context)


# ===== PROJECTS CREATE & EDIT =====

@login_required(login_url='accounts:login')
@require_http_methods(["GET", "POST"])
def project_create(request):
    """Create a new project."""
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        description = request.POST.get('description', '').strip()
        
        try:
            # ✅ VALIDATIONS
            name = ProjectValidator.validate_name(name)
            description = ProjectValidator.validate_description(description)
            
            # ✅ CRÉER LE PROJET
            project = Project.objects.create(
                name=name,
                description=description,
                created_by=request.user,
            )
            
            # ✅ AJOUTER LE CRÉATEUR COMME ADMIN
            project.members.add(request.user)
            project.set_user_role(request.user, 'ADMIN')  # ✅ FIX VULN #7: Passer User object
            
            # ✅ AUDIT LOG
            log_action(
                user=request.user,
                action='CREATE_PROJECT',
                resource_type='Project',
                resource_id=project.id,
                resource_name=project.name,
                ip_address=get_client_ip(request)
            )
            
            messages.success(request, 'Project created successfully!')
            return redirect('tickets:project_detail', project_id=project.id)
        
        except ValidationError as e:
            messages.error(request, f'Validation error: {e.message}')
        except Exception as e:
            messages.error(request, f'Error creating project: {str(e)}')
    
    return render(request, 'tickets/project_form.html')


@login_required(login_url='accounts:login')
@require_project_role(['MANAGER', 'ADMIN'])
@require_http_methods(["GET", "POST"])
def project_edit(request, project_id, project=None):
    """
    Edit a project (MANAGER+ only).
    @require_project_role gère les vérifications.
    """
    if request.method == 'POST':
        name = request.POST.get('name', project.name).strip()
        description = request.POST.get('description', project.description).strip()
        
        try:
            # ✅ VALIDATIONS
            name = ProjectValidator.validate_name(name)
            description = ProjectValidator.validate_description(description)
            
            changes = {}
            if project.name != name:
                changes['name'] = f"{project.name} → {name}"
            if project.description != description:
                changes['description'] = "Modified"
            
            project.name = name
            project.description = description
            project.save()
            
            # ✅ AUDIT LOG
            log_action(
                user=request.user,
                action='UPDATE_PROJECT',
                resource_type='Project',
                resource_id=project.id,
                resource_name=project.name,
                details=changes,
                ip_address=get_client_ip(request)
            )
            
            messages.success(request, 'Project updated successfully!')
            return redirect('tickets:project_detail', project_id=project.id)
        
        except ValidationError as e:
            messages.error(request, f'Validation error: {e.message}')
        except Exception as e:
            messages.error(request, f'Error updating project: {str(e)}')
    
    return render(request, 'tickets/project_form.html', {'project': project})


# ===== PROJECT MEMBERS MANAGEMENT =====

@login_required(login_url='accounts:login')
@require_project_role(['MANAGER', 'ADMIN'])
def manage_members(request, project_id, project=None):
    """
    Gère les membres du projet.
    
    FIX VULN #6: Utiliser .values() au lieu de .values_dict()
    """
    current_members = project.members.all()
    available_users = User.objects.exclude(id__in=current_members.values_list('id', flat=True))
    
    # ✅ FIX VULN #6: values() au lieu de values_dict()
    member_roles = ProjectMember.objects.filter(project=project).values('user_id', 'role')
    member_roles_dict = {m['user_id']: m['role'] for m in member_roles}
    
    context = {
        'project': project,
        'current_members': current_members,
        'available_users': available_users,
        'member_roles': member_roles_dict,
    }
    
    return render(request, 'tickets/project_members.html', context)


@login_required(login_url='accounts:login')
@require_project_role(['MANAGER', 'ADMIN'])
@require_http_methods(["POST"])
def add_member(request, project_id, project=None):
    """
    Ajoute un nouveau membre au projet.
    POST only pour éviter CSRF.
    """
    user_id = request.POST.get('user_id', '').strip()
    role = request.POST.get('role', 'USER').strip()
    
    try:
        # ✅ VALIDATIONS
        if not user_id:
            raise ValidationError("User ID is required.")
        
        user_id = int(user_id)
        if role not in ['USER', 'MANAGER', 'ADMIN']:
            raise ValidationError("Invalid role.")
        
        new_user = User.objects.get(id=user_id)
        
        # ✅ AJOUTER LE MEMBRE
        project.add_member(new_user, role)
        
        # ✅ AUDIT LOG
        log_action(
            user=request.user,
            action='ADD_MEMBER',
            resource_type='Project',
            resource_id=project.id,
            resource_name=project.name,
            details={'new_member': new_user.username, 'role': role},
            ip_address=get_client_ip(request)
        )
        
        messages.success(request, f'{new_user.username} added as {role}.')
    
    except ValidationError as e:
        messages.error(request, f'Validation error: {e.message}')
    except User.DoesNotExist:
        messages.error(request, 'User not found.')
    except Exception as e:
        messages.error(request, f'Error adding member: {str(e)}')
    
    return redirect('tickets:manage_members', project_id=project_id)


@login_required(login_url='accounts:login')
@require_project_role(['MANAGER', 'ADMIN'])
@require_http_methods(["POST"])
def update_member_role(request, project_id, member_id, project=None):
    """
    Met à jour le rôle d'un membre.
    POST only pour éviter CSRF.
    """
    member = get_object_or_404(User, id=member_id)
    
    # ✅ Ne pas laisser modifier le Owner
    if project.created_by == member:
        messages.error(request, 'Cannot change the Project Owner role.')
        return redirect('tickets:manage_members', project_id=project_id)
    
    new_role = request.POST.get('role', 'USER').strip()
    
    try:
        # ✅ VALIDATIONS
        if new_role not in ['USER', 'MANAGER', 'ADMIN']:
            raise ValidationError("Invalid role.")
        
        old_role = project.get_user_role(member)
        project.set_user_role(member, new_role)
        
        # ✅ AUDIT LOG
        log_action(
            user=request.user,
            action='CHANGE_ROLE',
            resource_type='Project',
            resource_id=project.id,
            resource_name=project.name,
            details={'member': member.username, 'old_role': old_role, 'new_role': new_role},
            ip_address=get_client_ip(request)
        )
        
        messages.success(request, f'{member.username} role changed to {new_role}.')
    
    except ValidationError as e:
        messages.error(request, f'Validation error: {e.message}')
    except Exception as e:
        messages.error(request, f'Error updating role: {str(e)}')
    
    return redirect('tickets:manage_members', project_id=project_id)


@login_required(login_url='accounts:login')
@require_project_role(['MANAGER', 'ADMIN'])
@require_http_methods(["POST"])
def remove_member(request, project_id, member_id, project=None):
    """
    Retire un membre du projet.
    
    FIX VULN #8: POST only (pas de GET deletion)
    """
    member = get_object_or_404(User, id=member_id)
    
    # ✅ Ne pas retirer le Owner
    if project.created_by == member:
        messages.error(request, 'Cannot remove the Project Owner.')
        return redirect('tickets:manage_members', project_id=project_id)
    
    try:
        project.remove_member(member)
        
        # ✅ AUDIT LOG
        log_action(
            user=request.user,
            action='REMOVE_MEMBER',
            resource_type='Project',
            resource_id=project.id,
            resource_name=project.name,
            details={'removed_member': member.username},
            ip_address=get_client_ip(request)
        )
        
        messages.success(request, f'{member.username} removed from the project.')
    
    except Exception as e:
        messages.error(request, f'Error removing member: {str(e)}')
    
    return redirect('tickets:manage_members', project_id=project_id)
