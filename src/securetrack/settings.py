from pathlib import Path
import os
from dotenv import load_dotenv

# Charger les variables du fichier .env
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/6.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv('SECRET_KEY', 'unsafe-dev-key-change-in-prod')


# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv('DEBUG', 'True') == 'True'


ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')



# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'csp',  # ✅ NOUVEAU - django-csp
    'core',
    'accounts',
    'rest_framework',
    'tickets',
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticatedOrReadOnly',
    ],
    'DEFAULT_THROTTLE_CLASSES': [  # ✅ NOUVEAU - Rate limiting DRF
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour'
    }
}

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',  
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'csp.middleware.CSPMiddleware',  # ✅ NOUVEAU - CSP middleware
    'securetrack.middleware.RateLimitMiddleware',  # ✅ NOUVEAU - Rate limit middleware
]


ROOT_URLCONF = 'securetrack.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

STATIC_URL = '/static/'
STATICFILES_DIRS = [os.path.join(BASE_DIR, 'static')]

WSGI_APPLICATION = 'securetrack.wsgi.application'


# Database
# https://docs.djangoproject.com/en/6.0/ref/settings/#databases

# Use SQLite locally (for development), PostgreSQL in Docker/Production
if os.getenv('USE_SQLITE', 'True') == 'True':
    # Local development with SQLite
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }
else:
    # Production/Docker with PostgreSQL
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.getenv('DATABASE_NAME', 'securetrack'),
            'USER': os.getenv('DATABASE_USER', 'securetrack_user'),
            'PASSWORD': os.getenv('DATABASE_PASSWORD', 'securetrack_pass_dev'),
            'HOST': os.getenv('DATABASE_HOST', 'localhost'),
            'PORT': os.getenv('DATABASE_PORT', '5432'),
        }
    }




# Password validation
# https://docs.djangoproject.com/en/6.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/6.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/6.0/howto/static-files/

STATIC_URL = 'static/'


# ===== SECURITY SETTINGS (S7 HARDENING) =====

# HTTPS (sera True en production)
SECURE_SSL_REDIRECT = os.getenv('DEBUG', 'True') != 'True'
SESSION_COOKIE_SECURE = os.getenv('DEBUG', 'True') != 'True'
CSRF_COOKIE_SECURE = os.getenv('DEBUG', 'True') != 'True'

# Cookies sécurisés
SESSION_COOKIE_HTTPONLY = True  # JS ne peut pas accéder au cookie
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_SAMESITE = 'Strict'

# Headers de sécurité (S7)
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0  # 1 year en prod
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG  # ✅ NOUVEAU - HSTS preload
X_FRAME_OPTIONS = 'DENY'
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_OPTIONS = 'nosniff'

# ✅ CSP RESSERRIE (S7) - Enlever 'unsafe-inline'
SECURE_CONTENT_SECURITY_POLICY = {
    'default-src': ("'self'",),
    'script-src': ("'self'", "cdn.jsdelivr.net"),  # ✅ CDN whitelist
    'style-src': ("'self'", "cdn.jsdelivr.net", "fonts.googleapis.com"),  # ✅ Enlever unsafe-inline
    'font-src': ("'self'", "fonts.gstatic.com"),
    'img-src': ("'self'", "data:", "https:"),
    'connect-src': ("'self'",),
    'frame-ancestors': ("'none'",),  # ✅ NOUVEAU - Strict frame policy
    'base-uri': ("'self'",),  # ✅ NOUVEAU - Prevent base tag injection
    'form-action': ("'self'",),  # ✅ NOUVEAU - Restrict form submissions
}

# ✅ NOUVEAU - Referrer Policy
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# ✅ NOUVEAU - Permissions Policy (Feature Policy)
PERMISSIONS_POLICY = {
    'geolocation': [],
    'microphone': [],
    'camera': [],
    'payment': [],
}

# ===== LOGGING (S8+) =====
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'django.log'),
            'formatter': 'verbose',
        },
        'security_file': {  # ✅ NOUVEAU - Security log
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'security.log'),
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.security': {  # ✅ NOUVEAU - Security logger
            'handlers': ['security_file'],
            'level': 'WARNING',
            'propagate': False,
        },
    },
}

# ✅ NOUVEAU - Rate limiting settings
RATE_LIMIT_ATTEMPTS = 5
RATE_LIMIT_PERIOD = 900  # 15 minutes en secondes

# ===== AUTH CUSTOM USER MODEL =====
AUTH_USER_MODEL = 'accounts.User'

# À la fin du fichier
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
]

# Media files (uploads utilisateurs)
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Error pages
HANDLER404 = 'core.views.custom_404'
HANDLER500 = 'core.views.custom_500'

# ✅ NOUVEAU - Create logs directory if it doesn't exist
import logging.handlers
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)
