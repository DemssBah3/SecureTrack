"""
Serializers for authentication endpoints.
Valide les données d'entrée (signup, login, etc.).
"""
import re
from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

User = get_user_model()


class SignupForm(forms.Form):
    """
    Formulaire d'inscription.
    Valide email, username, password.
    """
    
    email = forms.EmailField(
        max_length=254,
        required=True,
        error_messages={
            'required': 'L\'email est requis.',
            'invalid': 'Format email invalide.',
        }
    )
    
    username = forms.CharField(
        max_length=150,
        min_length=3,
        required=True,
        error_messages={
            'required': 'Le username est requis.',
            'min_length': 'Le username doit avoir au moins 3 caractères.',
            'max_length': 'Le username ne doit pas dépasser 150 caractères.',
        }
    )
    
    password = forms.CharField(
        widget=forms.PasswordInput,
        required=True,
        error_messages={
            'required': 'Le mot de passe est requis.',
        }
    )
    
    password_confirm = forms.CharField(
        widget=forms.PasswordInput,
        required=True,
        error_messages={
            'required': 'La confirmation du mot de passe est requise.',
        }
    )
    
    def clean(self):
        """Vérifier que les mots de passe correspondent"""
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')
        
        if password and password_confirm:
            if password != password_confirm:
                raise ValidationError("Les mots de passe ne correspondent pas.")
        
        return cleaned_data
    
    def clean_email(self):
        """Vérifier que l'email n'existe pas déjà"""
        email = self.cleaned_data.get('email')
        
        if User.objects.filter(email=email).exists():
            raise ValidationError("Cet email est déjà utilisé.")
        return email
    
    def clean_username(self):
        """Vérifier que l'username n'existe pas déjà"""
        username = self.cleaned_data.get('username')
        
        # Vérifier caractères valides (alphanumérique, _, -)
        if not re.match(r'^[\w-]+$', username):
            raise ValidationError(
                "Le username ne peut contenir que des lettres, chiffres, - et _."
            )
        
        if User.objects.filter(username=username).exists():
            raise ValidationError("Ce username est déjà pris.")
        
        return username
    
    def clean_password(self):
        """Valider la force du mot de passe"""
        password = self.cleaned_data.get('password')
        
        if not password:
            return password
        
        # Validation Django built-in
        try:
            validate_password(password)
        except ValidationError as e:
            raise ValidationError(f"Mot de passe faible : {e.messages[0]}")
        
        return password


class LoginForm(forms.Form):
    """
    Formulaire de connexion.
    Email + password.
    """
    
    email = forms.EmailField(
        max_length=254,
        required=True,
        error_messages={
            'required': 'L\'email est requis.',
            'invalid': 'Format email invalide.',
        }
    )
    
    password = forms.CharField(
        widget=forms.PasswordInput,
        required=True,
        error_messages={
            'required': 'Le mot de passe est requis.',
        }
    )
