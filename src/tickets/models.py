from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()

# Role choices
ROLE_CHOICES = [
    ('USER', 'User'),
    ('MANAGER', 'Manager'),
    ('ADMIN', 'Admin'),
]


class Role(models.Model):
    """Role model for RBAC."""
    name = models.CharField(max_length=50, choices=ROLE_CHOICES, unique=True)
    permissions = models.JSONField(default=dict)  # {permission: True/False}
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['name']


class Project(models.Model):
    """Project model with members and RBAC."""
    name = models.CharField(max_length=255)
    description = models.TextField()
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_projects')
    members = models.ManyToManyField(User, through='ProjectMember', related_name='projects')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name

    class Meta:
        ordering = ['-created_at']

    def get_user_role(self, user):
        """Récupère le rôle d'un utilisateur dans ce projet"""
        if self.created_by == user:
            return 'ADMIN'  # Owner est toujours ADMIN
        
        try:
            membership = ProjectMember.objects.get(project=self, user=user)
            return membership.role
        except ProjectMember.DoesNotExist:
            return None
    
    def set_user_role(self, user, role):
        """Définit le rôle d'un utilisateur"""
        if role not in ['USER', 'MANAGER', 'ADMIN']:
            raise ValueError(f"Invalid role: {role}")
        
        membership, created = ProjectMember.objects.get_or_create(
            project=self,
            user=user
        )
        membership.role = role
        membership.save()
    
    def add_member(self, user, role='USER'):
        """Ajoute un utilisateur comme membre avec un rôle"""
        if user not in self.members.all():
            self.members.add(user)
        self.set_user_role(user, role)
    
    def remove_member(self, user):
        """Retire un utilisateur du projet"""
        ProjectMember.objects.filter(project=self, user=user).delete()
        self.members.remove(user)
    
    def is_member(self, user):
        """Vérifie si un utilisateur est membre du projet"""
        return user in self.members.all() or self.created_by == user


class Ticket(models.Model):
    """Ticket model with RBAC controls."""
    STATUS_CHOICES = [
        ('OPEN', 'Open'),
        ('IN_PROGRESS', 'In Progress'),
        ('CLOSED', 'Closed'),
    ]
    PRIORITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
    ]

    title = models.CharField(max_length=255)
    description = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='tickets')
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tickets_created')
    assigned_to = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='tickets_assigned'
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='OPEN')
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='MEDIUM')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

    class Meta:
        ordering = ['-created_at']


class ProjectMember(models.Model):
    """Through model to track member roles"""
    ROLE_CHOICES = [
        ('USER', 'User'),
        ('MANAGER', 'Manager'),
        ('ADMIN', 'Admin'),
    ]
    
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='USER')
    added_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ('project', 'user')
    
    def __str__(self):
        return f"{self.project.name} - {self.user.username} ({self.role})"


class AuditLog(models.Model):
    """Audit log pour traçabilité des actions"""
    ACTION_CHOICES = [
        ('CREATE_TICKET', 'Create Ticket'),
        ('UPDATE_TICKET', 'Update Ticket'),
        ('DELETE_TICKET', 'Delete Ticket'),
        ('CREATE_PROJECT', 'Create Project'),
        ('UPDATE_PROJECT', 'Update Project'),
        ('ADD_MEMBER', 'Add Member'),
        ('REMOVE_MEMBER', 'Remove Member'),
        ('CHANGE_ROLE', 'Change Role'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='audit_logs')
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    resource_type = models.CharField(max_length=50)  # 'Ticket', 'Project', 'Member'
    resource_id = models.IntegerField()
    resource_name = models.CharField(max_length=255, blank=True)
    details = models.JSONField(default=dict)  # {'old_status': 'OPEN', 'new_status': 'CLOSED'}
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['action', '-timestamp']),
            models.Index(fields=['resource_type', 'resource_id']),
        ]
    
    def __str__(self):
        return f"{self.action} by {self.user} on {self.timestamp}"
