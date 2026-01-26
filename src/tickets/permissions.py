"""
Permission decorators for RBAC in SecureTrack.
Enhanced with audit logging and helper functions.

OWASP A01:2021 - Broken Access Control Prevention
"""

from functools import wraps
from django.shortcuts import redirect, get_object_or_404
from django.contrib import messages
from django.http import HttpResponseForbidden
from django.contrib.auth import get_user_model
from .models import Project, Ticket, AuditLog

User = get_user_model()


def get_client_ip(request):
    """Extrait l'IP du client (même derrière un proxy)."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def log_action(user, action, resource_type, resource_id, resource_name='', details=None, ip_address=None):
    """
    Helper pour logger les actions utilisateurs dans AuditLog.
    
    Utilisation:
    log_action(request.user, 'UPDATE_TICKET', 'Ticket', 5, 
               resource_name='Fix bug', details={'status': 'CLOSED'},
               ip_address=get_client_ip(request))
    """
    AuditLog.objects.create(
        user=user,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_name=resource_name,
        details=details or {},
        ip_address=ip_address,
    )


def require_project_role(required_role='USER'):
    """
    Decorator to check user role in project.
    
    Usage:
    @require_project_role('MANAGER')
    def my_view(request, project_id):
        ...
    
    Role hierarchy:
    - USER: 0 (basic member)
    - MANAGER: 1 (can manage tickets and members)
    - ADMIN: 2 (full control, can delete project)
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, project_id=None, *args, **kwargs):
            # ✅ Check authentication
            if not request.user.is_authenticated:
                messages.error(request, 'You must be logged in.')
                return redirect('accounts:login')
            
            # ✅ If no project_id, proceed
            if not project_id:
                return view_func(request, *args, **kwargs)
            
            # ✅ Get project or 404
            try:
                project = Project.objects.get(id=project_id)
            except Project.DoesNotExist:
                messages.error(request, 'Project not found.')
                return redirect('tickets:project_list')
            
            # ✅ Check if user is member
            if not project.is_member(request.user):
                messages.error(request, 'You do not have access to this project.')
                # Log unauthorized access attempt
                log_action(
                    user=request.user,
                    action='ACCESS_DENIED',
                    resource_type='Project',
                    resource_id=project.id,
                    resource_name=project.name,
                    details={'reason': 'Not a member'},
                    ip_address=get_client_ip(request)
                )
                return redirect('tickets:project_list')
            
            # ✅ Check role hierarchy
            user_role = project.get_user_role(request.user)
            role_hierarchy = {'USER': 0, 'MANAGER': 1, 'ADMIN': 2}
            
            required_level = role_hierarchy.get(required_role, 0)
            user_level = role_hierarchy.get(user_role, 0)
            
            if user_level < required_level:
                messages.error(request, f'You need at least {required_role} role to access this resource.')
                # Log unauthorized role attempt
                log_action(
                    user=request.user,
                    action='PERMISSION_DENIED',
                    resource_type='Project',
                    resource_id=project.id,
                    resource_name=project.name,
                    details={'required_role': required_role, 'user_role': user_role},
                    ip_address=get_client_ip(request)
                )
                return HttpResponseForbidden('Forbidden: Insufficient permissions')
            
            # ✅ Pass project to view as keyword argument
            kwargs['project'] = project
            return view_func(request, project_id=project_id, *args, **kwargs)
        
        return wrapper
    return decorator


def require_ticket_permission(permission='view'):
    """
    Decorator to check ticket permissions.
    
    Usage:
    @require_ticket_permission('edit')
    def ticket_edit(request, ticket_id):
        ...
    
    Permissions:
    - 'view': user must be member of project
    - 'edit': creator or MANAGER+ can edit
    - 'delete': creator or ADMIN only
    
    OWASP A01:2021 - Broken Access Control
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, ticket_id=None, *args, **kwargs):
            # ✅ Check authentication
            if not request.user.is_authenticated:
                messages.error(request, 'You must be logged in.')
                return redirect('accounts:login')
            
            # ✅ If no ticket_id, proceed
            if not ticket_id:
                return view_func(request, *args, **kwargs)
            
            # ✅ Get ticket or 404
            try:
                ticket = Ticket.objects.get(id=ticket_id)
            except Ticket.DoesNotExist:
                messages.error(request, 'Ticket not found.')
                return redirect('tickets:ticket_list')
            
            project = ticket.project
            
            # ✅ Check if user is project member (FIX VULN #2)
            if not project.is_member(request.user):
                messages.error(request, 'You do not have access to this ticket.')
                # Log unauthorized access
                log_action(
                    user=request.user,
                    action='ACCESS_DENIED',
                    resource_type='Ticket',
                    resource_id=ticket.id,
                    resource_name=ticket.title,
                    details={'reason': 'Not a project member'},
                    ip_address=get_client_ip(request)
                )
                return HttpResponseForbidden('Forbidden: Access denied')
            
            user_role = project.get_user_role(request.user)
            
            # ✅ PERMISSION: VIEW
            if permission == 'view':
                # All members can view
                pass  # Already checked membership above
            
            # ✅ PERMISSION: EDIT (FIX VULN #2)
            elif permission == 'edit':
                is_creator = ticket.created_by == request.user
                can_edit = is_creator or user_role in ['MANAGER', 'ADMIN']
                
                if not can_edit:
                    messages.error(request, 'You do not have permission to edit this ticket.')
                    # Log unauthorized edit attempt
                    log_action(
                        user=request.user,
                        action='PERMISSION_DENIED',
                        resource_type='Ticket',
                        resource_id=ticket.id,
                        resource_name=ticket.title,
                        details={'reason': 'Cannot edit', 'user_role': user_role},
                        ip_address=get_client_ip(request)
                    )
                    return HttpResponseForbidden('Forbidden: Cannot edit this ticket')
            
            # ✅ PERMISSION: DELETE (FIX VULN #2)
            elif permission == 'delete':
                is_creator = ticket.created_by == request.user
                can_delete = is_creator or user_role == 'ADMIN'
                
                if not can_delete:
                    messages.error(request, 'You do not have permission to delete this ticket.')
                    # Log unauthorized delete attempt
                    log_action(
                        user=request.user,
                        action='PERMISSION_DENIED',
                        resource_type='Ticket',
                        resource_id=ticket.id,
                        resource_name=ticket.title,
                        details={'reason': 'Cannot delete', 'user_role': user_role},
                        ip_address=get_client_ip(request)
                    )
                    return HttpResponseForbidden('Forbidden: Cannot delete this ticket')
            
            # ✅ Pass ticket to view as keyword argument
            kwargs['ticket'] = ticket
            return view_func(request, ticket_id=ticket_id, *args, **kwargs)
        
        return wrapper
    return decorator
