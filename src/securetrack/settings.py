from pathlib import Path
import os
from dotenv import load_dotenv

# Charger les variables du fichier .env
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# ============ ENVIRONMENT ============
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
DEBUG = os.getenv("DEBUG", "True") == "True"

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/6.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv("SECRET_KEY", "unsafe-dev-key-change-in-prod")

# SECURITY WARNING: don't run with debug turned on in production!
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1,testserver,*").split(",")


# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "csp",  # ✅ NOUVEAU - django-csp
    "core",
    "accounts",
    "rest_framework",
    "tickets",
]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticatedOrReadOnly",
    ],
    "DEFAULT_THROTTLE_CLASSES": [  # ✅ NOUVEAU - Rate limiting DRF
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {"anon": "100/hour", "user": "1000/hour"},
}

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "csp.middleware.CSPMiddleware",  # ✅ NOUVEAU - CSP middleware
    "securetrack.middleware.RateLimitMiddleware",  # ✅ NOUVEAU - Rate limit middleware
]


ROOT_URLCONF = "securetrack.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [os.path.join(BASE_DIR, "templates")],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "securetrack.wsgi.application"


# ============ DATABASE ============
# Use SQLite locally (for development), PostgreSQL in Docker/Production
if os.getenv("USE_SQLITE", "True") == "True":
    # Local development with SQLite
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }
else:
    # Production/Docker with PostgreSQL
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("DATABASE_NAME", "securetrack"),
            "USER": os.getenv("DATABASE_USER", "securetrack_user"),
            "PASSWORD": os.getenv("DATABASE_PASSWORD", "securetrack_pass_dev"),
            "HOST": os.getenv("DATABASE_HOST", "localhost"),
            "PORT": os.getenv("DATABASE_PORT", "5432"),
        }
    }


# Password validation
# https://docs.djangoproject.com/en/6.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {
            "min_length": 8,
        },
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/6.0/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# ============ SECURITY - CONDITIONAL (test vs dev vs prod) ============
# En test (DEBUG=True ET ENVIRONMENT=test): désactiver HTTPS
# En dev (DEBUG=True): flexible
# En prod (DEBUG=False): activer HTTPS

if DEBUG and ENVIRONMENT == "test":
    # ✅ TEST ENVIRONMENT: désactiver HTTPS redirects
    SECURE_SSL_REDIRECT = False
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    SECURE_HSTS_SECONDS = 0
    SECURE_HSTS_INCLUDE_SUBDOMAINS = False
    SECURE_HSTS_PRELOAD = False
else:
    # PRODUCTION/DEVELOPMENT: activer HTTPS en prod
    SECURE_SSL_REDIRECT = not DEBUG  # True en prod, False en dev
    SESSION_COOKIE_SECURE = not DEBUG
    CSRF_COOKIE_SECURE = not DEBUG
    SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0  # 1 year en prod, 0 en dev
    SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
    SECURE_HSTS_PRELOAD = not DEBUG

# Cookies sécurisés (toujours activé)
SESSION_COOKIE_HTTPONLY = True  # JS ne peut pas accéder au cookie
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_SAMESITE = "Strict"

# Headers de sécurité (S7)
X_FRAME_OPTIONS = "DENY"
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_OPTIONS = "nosniff"

# ✅ CSP RESSERRIE (S7) - Enlever 'unsafe-inline'
SECURE_CONTENT_SECURITY_POLICY = {
    "default-src": ("'self'",),
    "script-src": ("'self'", "cdn.jsdelivr.net"),  # ✅ CDN whitelist
    "style-src": ("'self'", "cdn.jsdelivr.net", "fonts.googleapis.com"),  # ✅ Enlever unsafe-inline
    "font-src": ("'self'", "fonts.gstatic.com"),
    "img-src": ("'self'", "data:", "https:"),
    "connect-src": ("'self'",),
    "frame-ancestors": ("'none'",),  # ✅ Strict frame policy
    "base-uri": ("'self'",),  # ✅ Prevent base tag injection
    "form-action": ("'self'",),  # ✅ Restrict form submissions
}

# ✅ Referrer Policy
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"

# ✅ Permissions Policy (Feature Policy)
PERMISSIONS_POLICY = {
    "geolocation": [],
    "microphone": [],
    "camera": [],
    "payment": [],
}


# ============ STATIC & MEDIA FILES ============
STATIC_URL = "/static/"
STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static"),
]

# Media files (uploads utilisateurs)
MEDIA_URL = "/media/"
MEDIA_ROOT = os.path.join(BASE_DIR, "media")


# ============ LOGGING ============
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {process:d} {thread:d} {message}",
            "style": "{",
        },
        "simple": {
            "format": "{levelname} {asctime} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "simple",
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": os.path.join(BASE_DIR, "logs", "django.log"),
            "formatter": "verbose",
        },
        "security_file": {  # ✅ Security log
            "class": "logging.FileHandler",
            "filename": os.path.join(BASE_DIR, "logs", "security.log"),
            "formatter": "verbose",
        },
    },
    "loggers": {
        "django": {
            "handlers": ["console", "file"],
            "level": "INFO",
            "propagate": False,
        },
        "django.security": {  # ✅ Security logger
            "handlers": ["security_file"],
            "level": "WARNING",
            "propagate": False,
        },
    },
}


# ============ RATE LIMITING ============
RATE_LIMIT_ATTEMPTS = 5
RATE_LIMIT_PERIOD = 900  # 15 minutes en secondes


# ============ AUTH CUSTOM USER MODEL ============
AUTH_USER_MODEL = "accounts.User"


# ============ ERROR HANDLERS ============
HANDLER404 = "core.views.custom_404"
HANDLER500 = "core.views.custom_500"


# ============ CREATE LOGS DIRECTORY ============
LOGS_DIR = os.path.join(BASE_DIR, "logs")
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)


# ============ DEFAULT AUTO FIELD ============
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
