from django.test import TestCase
from django.contrib.auth import get_user_model
from tickets.models import Project, Ticket, ProjectMember, Role

User = get_user_model()

# ...existing tests...
