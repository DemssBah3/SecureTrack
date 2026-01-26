from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    # ✅ Routes: /auth/signup/, /auth/login/, etc. (prefix 'auth/' added by securetrack/urls.py)
    path('signup/', views.signup, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('me/', views.me, name='me'),
    # path('profile/', views.profile, name='profile'),  # ❌ REMOVED (doesn't exist)
    path('2fa/setup/', views.setup_2fa, name='setup_2fa'),
    path('2fa/verify/', views.verify_2fa, name='verify_2fa'),
    path('2fa/disable/', views.disable_2fa, name='disable_2fa'),
    path('backup-codes/', views.get_backup_codes, name='get_backup_codes'),
    path('verify-totp-login/', views.verify_totp_login, name='verify_totp_login'),
]
