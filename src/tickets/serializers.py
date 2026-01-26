"""
Form serializers pour validation et rendu formulaires.
"""

from django import forms
from .models import Ticket, Project
from .validators import TicketValidator, ProjectValidator


class TicketForm(forms.ModelForm):
    """Form pour créer/éditer tickets."""
    
    class Meta:
        model = Ticket
        fields = ['title', 'description', 'status', 'priority', 'assigned_to']
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Ticket title',
                'maxlength': '255',
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Ticket description',
                'rows': 5,
                'maxlength': '5000',
            }),
            'status': forms.Select(attrs={
                'class': 'form-select',
            }),
            'priority': forms.Select(attrs={
                'class': 'form-select',
            }),
            'assigned_to': forms.Select(attrs={
                'class': 'form-select',
            }),
        }
    
    def clean_title(self):
        title = self.cleaned_data.get('title')
        return TicketValidator.validate_title(title)
    
    def clean_description(self):
        description = self.cleaned_data.get('description')
        return TicketValidator.validate_description(description)
    
    def clean_status(self):
        status = self.cleaned_data.get('status')
        return TicketValidator.validate_status(status)
    
    def clean_priority(self):
        priority = self.cleaned_data.get('priority')
        return TicketValidator.validate_priority(priority)


class ProjectForm(forms.ModelForm):
    """Form pour créer/éditer projets."""
    
    class Meta:
        model = Project
        fields = ['name', 'description']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Project name',
                'maxlength': '255',
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Project description',
                'rows': 4,
                'maxlength': '2000',
            }),
        }
    
    def clean_name(self):
        name = self.cleaned_data.get('name')
        return ProjectValidator.validate_name(name)
    
    def clean_description(self):
        description = self.cleaned_data.get('description')
        return ProjectValidator.validate_description(description)
