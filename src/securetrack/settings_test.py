"""
Test settings - Disable HTTPS redirects
"""

from .settings import *

# Disable HTTPS for tests
DEBUG = True
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_HSTS_SECONDS = 0
ALLOWED_HOSTS = ["*", "testserver", "127.0.0.1"]

# In-memory SQLite
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}
