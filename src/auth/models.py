"""
Custom User model for SecureTrack.
Utilise le AbstractUser de Django pour étendre le modèle User par défaut.
"""
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone


class User(AbstractUser):
    """
    Modèle User personnalisé.
    
    Champs supplémentaires :
    - last_password_change : date du dernier changement de mdp
    - password_change_required : force changement mdp au login suivant
    - account_locked : compte verrouillé après tentatives échouées
    - locked_until : timestamp jusqu'où le compte est verrouillé
    """
    
    # Métadonnées
    created_at = models.DateTimeField(auto_now_add=True, help_text="Créé le")
    updated_at = models.DateTimeField(auto_now=True, help_text="Modifié le")
    
    # Sécurité mots de passe
    last_password_change = models.DateTimeField(
        default=timezone.now,
        help_text="Date du dernier changement de mot de passe"
    )
    password_change_required = models.BooleanField(
        default=False,
        help_text="Forcer changement mdp au prochain login"
    )
    
    # Sécurité compte (brute-force protection)
    account_locked = models.BooleanField(
        default=False,
        help_text="Compte verrouillé après trop de tentatives échouées"
    )
    locked_until = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Jusqu'à quand le compte est verrouillé"
    )
    failed_login_attempts = models.IntegerField(
        default=0,
        help_text="Nombre de tentatives login échouées"
    )
    
    # 2FA (sera utilisé en S4)
    totp_enabled = models.BooleanField(
        default=False,
        help_text="2FA TOTP activé"
    )
    totp_secret = models.CharField(
        max_length=32,
        blank=True,
        help_text="Secret TOTP chiffré (à implémenter)"
    )
    
    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"
        ordering = ['-date_joined']
    
    def __str__(self):
        return f"{self.username} ({self.email})"
    
    def is_account_locked(self):
        """Vérifier si le compte est actuellement verrouillé"""
        if not self.account_locked:
            return False
        
        if self.locked_until and timezone.now() > self.locked_until:
            # Le verrouillage a expiré
            self.account_locked = False
            self.locked_until = None
            self.failed_login_attempts = 0
            self.save()
            return False
        
        return True
    
    def unlock_account(self):
        """Déverrouiller le compte"""
        self.account_locked = False
        self.locked_until = None
        self.failed_login_attempts = 0
        self.save()
    
    def increment_failed_login(self):
        """Incrémenter les tentatives échouées"""
        self.failed_login_attempts += 1
        
        # Si 5 tentatives échouées : verrouiller pendant 15 min
        if self.failed_login_attempts >= 5:
            self.account_locked = True
            self.locked_until = timezone.now() + timezone.timedelta(minutes=15)
        
        self.save()
    
    def reset_failed_login(self):
        """Réinitialiser les tentatives échouées"""
        self.failed_login_attempts = 0
        self.account_locked = False
        self.locked_until = None
        self.save()
