"""
Validation helpers pour inputs utilisateurs.
OWASP A03:2021 - Injection Prevention
"""

from django.core.exceptions import ValidationError
from django.utils.html import escape
import re


class TicketValidator:
    """Validateurs pour tickets"""
    
    MAX_TITLE_LENGTH = 255
    MIN_TITLE_LENGTH = 3
    MAX_DESCRIPTION_LENGTH = 5000
    MIN_DESCRIPTION_LENGTH = 10
    
    @staticmethod
    def validate_title(title):
        """Valide le titre du ticket"""
        if not title or not isinstance(title, str):
            raise ValidationError("Title is required and must be a string.")
        
        title = title.strip()
        
        if len(title) < TicketValidator.MIN_TITLE_LENGTH:
            raise ValidationError(f"Title must be at least {TicketValidator.MIN_TITLE_LENGTH} characters.")
        
        if len(title) > TicketValidator.MAX_TITLE_LENGTH:
            raise ValidationError(f"Title must be at most {TicketValidator.MAX_TITLE_LENGTH} characters.")
        
        # Check pour caractères valides
        if not re.match(r'^[a-zA-Z0-9\s\-.,!?():#&\'\"]+$', title):
            raise ValidationError("Title contains invalid characters.")
        
        return escape(title)
    
    @staticmethod
    def validate_description(description):
        """Valide la description du ticket"""
        if not description or not isinstance(description, str):
            raise ValidationError("Description is required and must be a string.")
        
        description = description.strip()
        
        if len(description) < TicketValidator.MIN_DESCRIPTION_LENGTH:
            raise ValidationError(f"Description must be at least {TicketValidator.MIN_DESCRIPTION_LENGTH} characters.")
        
        if len(description) > TicketValidator.MAX_DESCRIPTION_LENGTH:
            raise ValidationError(f"Description must be at most {TicketValidator.MAX_DESCRIPTION_LENGTH} characters.")
        
        return escape(description)
    
    @staticmethod
    def validate_status(status):
        """Valide le statut du ticket"""
        valid_statuses = ['OPEN', 'IN_PROGRESS', 'CLOSED']
        
        if status not in valid_statuses:
            raise ValidationError(f"Invalid status. Must be one of: {', '.join(valid_statuses)}")
        
        return status
    
    @staticmethod
    def validate_priority(priority):
        """Valide la priorité du ticket"""
        valid_priorities = ['LOW', 'MEDIUM', 'HIGH']
        
        if priority not in valid_priorities:
            raise ValidationError(f"Invalid priority. Must be one of: {', '.join(valid_priorities)}")
        
        return priority


class ProjectValidator:
    """Validateurs pour projets"""
    
    MAX_NAME_LENGTH = 255
    MIN_NAME_LENGTH = 3
    MAX_DESCRIPTION_LENGTH = 2000
    MIN_DESCRIPTION_LENGTH = 10
    
    @staticmethod
    def validate_name(name):
        """Valide le nom du projet"""
        if not name or not isinstance(name, str):
            raise ValidationError("Project name is required and must be a string.")
        
        name = name.strip()
        
        if len(name) < ProjectValidator.MIN_NAME_LENGTH:
            raise ValidationError(f"Project name must be at least {ProjectValidator.MIN_NAME_LENGTH} characters.")
        
        if len(name) > ProjectValidator.MAX_NAME_LENGTH:
            raise ValidationError(f"Project name must be at most {ProjectValidator.MAX_NAME_LENGTH} characters.")
        
        if not re.match(r'^[a-zA-Z0-9\s\-.,()&\'\"]+$', name):
            raise ValidationError("Project name contains invalid characters.")
        
        return escape(name)
    
    @staticmethod
    def validate_description(description):
        """Valide la description du projet"""
        if not description or not isinstance(description, str):
            raise ValidationError("Project description is required and must be a string.")
        
        description = description.strip()
        
        if len(description) < ProjectValidator.MIN_DESCRIPTION_LENGTH:
            raise ValidationError(f"Description must be at least {ProjectValidator.MIN_DESCRIPTION_LENGTH} characters.")
        
        if len(description) > ProjectValidator.MAX_DESCRIPTION_LENGTH:
            raise ValidationError(f"Description must be at most {ProjectValidator.MAX_DESCRIPTION_LENGTH} characters.")
        
        return escape(description)


def get_client_ip(request):
    """Extrait l'IP du client (même derrière un proxy)"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
