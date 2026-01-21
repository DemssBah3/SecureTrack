"""
Authentication views for SecureTrack.
Signup, Login, Logout endpoints.
"""
import logging
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from .serializers import SignupForm, LoginForm

User = get_user_model()
logger = logging.getLogger(__name__)


def log_auth_event(user, event_type, success, ip_address, details=""):
    """
    Logger un événement d'authentification.
    Utilisé pour l'audit trail (S8+).
    
    Args:
        user: User object ou None
        event_type: 'signup', 'login', 'logout', 'login_failed', etc.
        success: True/False
        ip_address: IP de l'utilisateur
        details: détails supplémentaires
    """
    username = user.username if user else "unknown"
    status = "SUCCESS" if success else "FAILED"
    
    log_msg = f"AUTH_EVENT | {event_type} | {status} | user={username} | ip={ip_address}"
    if details:
        log_msg += f" | {details}"
    
    if success:
        logger.info(log_msg)
    else:
        logger.warning(log_msg)


def get_client_ip(request):
    """Récupérer l'IP du client"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


@require_http_methods(["POST"])
@csrf_exempt
def signup(request):
    """
    Endpoint d'inscription.
    
    POST /auth/signup/
    """
    
    ip_address = get_client_ip(request)
    
    # Parser les données POST
    form = SignupForm(request.POST)
    
    if not form.is_valid():
        # Erreurs de validation
        log_auth_event(None, 'signup', False, ip_address, 
                      details=f"Validation error: {form.errors}")
        return JsonResponse({
            'status': 'error',
            'message': 'Validation failed',
            'errors': form.errors,
        }, status=400)
    
    # Créer l'utilisateur
    try:
        email = form.cleaned_data['email']
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']
        
        user = User.objects.create_user(
            email=email,
            username=username,
            password=password,  # Automatiquement hashé par Django
        )
        
        log_auth_event(user, 'signup', True, ip_address)
        
        return JsonResponse({
            'status': 'success',
            'message': 'User created successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
            }
        }, status=201)
    
    except Exception as e:
        logger.error(f"Signup error: {str(e)}")
        log_auth_event(None, 'signup', False, ip_address, 
                      details=f"Exception: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'Signup failed. Please try again.',
        }, status=500)


@require_http_methods(["POST"])
@csrf_exempt
def login_view(request):
    """
    Endpoint de connexion.
    
    POST /auth/login/
    """
    
    ip_address = get_client_ip(request)
    
    # Parser les données POST
    form = LoginForm(request.POST)
    
    if not form.is_valid():
        log_auth_event(None, 'login', False, ip_address,
                      details=f"Validation error: {form.errors}")
        return JsonResponse({
            'status': 'error',
            'message': 'Email and password are required',
            'errors': form.errors,
        }, status=400)
    
    email = form.cleaned_data['email']
    password = form.cleaned_data['password']
    
    try:
        # Chercher l'utilisateur par email
        user = User.objects.get(email=email)
        
        # Vérifier si le compte est verrouillé
        if user.is_account_locked():
            log_auth_event(user, 'login', False, ip_address,
                          details="Account locked")
            return JsonResponse({
                'status': 'error',
                'message': 'Account locked. Try again in 15 minutes.',
            }, status=403)
        
        # Vérifier le mot de passe
        if not user.check_password(password):
            # ✅ INCRÉMENTER LES TENTATIVES ÉCHOUÉES
            user.increment_failed_login()
            log_auth_event(user, 'login', False, ip_address,
                          details=f"Invalid password (attempts: {user.failed_login_attempts})")
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid email or password',
            }, status=401)
        
        # ✅ PASSWORD EST CORRECT : réinitialiser les tentatives
        user.reset_failed_login()
        
        # Si 2FA est activé, demander le code TOTP
        if user.totp_enabled:
            # Stocker temporairement l'ID utilisateur pour la vérification 2FA
            request.session['pending_2fa_user_id'] = user.id

            log_auth_event(user, 'login', True, ip_address, details="2FA required")

            return JsonResponse({
                'status': 'success',
                'message': '2FA required',
                'data': {
                    'requires_2fa': True,
                }
            }, status=200)
            
        # Pas de 2FA : créer la session directement
        login(request, user)

        log_auth_event(user, 'login', True, ip_address)

        return JsonResponse({
                'status': 'success',
                'message': 'Login successful',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                }
            }, status=200)
    
    except User.DoesNotExist:
        log_auth_event(None, 'login', False, ip_address,
                      details="User not found")
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid email or password',
        }, status=401)
    
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        log_auth_event(None, 'login', False, ip_address,
                      details=f"Exception: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'Login failed. Please try again.',
        }, status=500)


@require_http_methods(["POST"])
@csrf_exempt
def logout_view(request):
    """
    Endpoint de déconnexion.
    
    POST /auth/logout/
    """
    
    ip_address = get_client_ip(request)
    
    if request.user.is_authenticated:
        user = request.user
        logout(request)
        log_auth_event(user, 'logout', True, ip_address)
        
        return JsonResponse({
            'status': 'success',
            'message': 'Logout successful',
        }, status=200)
    
    else:
        return JsonResponse({
            'status': 'error',
            'message': 'Not authenticated',
        }, status=401)


@require_http_methods(["GET"])
def me(request):
    """
    Endpoint pour récupérer les infos de l'utilisateur connecté.
    
    GET /auth/me/
    """
    
    if not request.user.is_authenticated:
        return JsonResponse({
            'status': 'error',
            'message': 'Not authenticated',
        }, status=401)
    
    user = request.user
    return JsonResponse({
        'status': 'success',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_staff': user.is_staff,
            'is_superuser': user.is_superuser,
            'date_joined': user.date_joined.isoformat(),
        }
    }, status=200)

@require_http_methods(["POST"])
@csrf_protect
def setup_2fa(request):
    """Endpoint pour démarrer l'activation TOTP."""
    if not request.user.is_authenticated:
        return JsonResponse({
            'status': 'error',
            'message': 'Not authenticated',
        }, status=401)
    
    user = request.user
    
    if user.totp_enabled:
        return JsonResponse({
            'status': 'error',
            'message': '2FA already enabled',
        }, status=400)  # ✅ Changé de 401 à 400
    
    try:
        from .totp_utils import generate_totp_secret, get_totp_uri, generate_qr_code, generate_backup_codes
        
        # Générer secret TOTP
        secret = generate_totp_secret()
        totp_uri = get_totp_uri(secret, user.email)
        qr_code_data = generate_qr_code(totp_uri)
        
        # Générer codes de secours
        backup_codes = generate_backup_codes(10)
        
        # Stocker temporairement en session
        request.session['temp_totp_secret'] = secret
        request.session['temp_backup_codes'] = backup_codes
        
        return JsonResponse({
            'status': 'success',
            'data': {
                'secret': secret,
                'qr_code': qr_code_data,
                'backup_codes': backup_codes,
            }
        }, status=200)
    except Exception as e:
        logger.error(f"Setup 2FA error: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'Setup failed',
        }, status=500)


@require_http_methods(["POST"])
@csrf_protect
def verify_2fa(request):
    """Endpoint pour vérifier et activer TOTP."""
    if not request.user.is_authenticated:
        return JsonResponse({
            'status': 'error',
            'message': 'Not authenticated',
        }, status=401)
    
    user = request.user
    
    if user.totp_enabled:
        return JsonResponse({
            'status': 'error',
            'message': '2FA already enabled',
        }, status=400)
    
    temp_secret = request.session.get('temp_totp_secret')
    if not temp_secret:
        return JsonResponse({
            'status': 'error',
            'message': 'Setup not initiated',
        }, status=400)
    
    code = request.POST.get('code', '').strip()
    if not code or len(code) != 6 or not code.isdigit():
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid code format',
        }, status=400)
    
    try:
        from .totp_utils import verify_totp
        
        if not verify_totp(temp_secret, code):
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid code',
            }, status=401)
        
        # Activer 2FA
        user.totp_enabled = True
        user.totp_secret = temp_secret
        user.save()
        
        # Nettoyer la session
        backup_codes = request.session.pop('temp_backup_codes', [])
        request.session.pop('temp_totp_secret', None)
        
        return JsonResponse({
            'status': 'success',
            'message': '2FA enabled successfully',
            'data': {
                'backup_codes': backup_codes,
            }
        }, status=200)
    except Exception as e:
        logger.error(f"Verify 2FA error: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'Verification failed',
        }, status=500)


@require_http_methods(["POST"])
@csrf_protect
def disable_2fa(request):
    """Endpoint pour désactiver TOTP."""
    if not request.user.is_authenticated:
        return JsonResponse({
            'status': 'error',
            'message': 'Not authenticated',
        }, status=401)
    
    user = request.user
    
    if not user.totp_enabled:
        return JsonResponse({
            'status': 'error',
            'message': '2FA not enabled',
        }, status=400)  # ✅ Changé de 401 à 400
    
    password = request.POST.get('password', '').strip()
    if not password:
        return JsonResponse({
            'status': 'error',
            'message': 'Password required',
        }, status=400)  # ✅ Changé de 401 à 400
    
    if not user.check_password(password):
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid password',
        }, status=401)
    
    try:
        user.totp_enabled = False
        user.totp_secret = ''
        user.save()
        
        return JsonResponse({
            'status': 'success',
            'message': '2FA disabled',
        }, status=200)
    except Exception as e:
        logger.error(f"Disable 2FA error: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'Disable failed',
        }, status=500)


@require_http_methods(["GET"])
def get_backup_codes(request):
    """Endpoint pour récupérer les codes de secours."""
    if not request.user.is_authenticated:
        return JsonResponse({
            'status': 'error',
            'message': 'Not authenticated',
        }, status=401)
    
    user = request.user
    
    if not user.totp_enabled:
        return JsonResponse({
            'status': 'error',
            'message': '2FA not enabled',
        }, status=400)
    
    return JsonResponse({
        'status': 'success',
        'data': {
            '2fa_enabled': True,
        }
    }, status=200)


@require_http_methods(["POST"])
@csrf_protect
def verify_totp_login(request):
    """Endpoint pour vérifier TOTP au login."""
    pending_user_id = request.session.get('pending_2fa_user_id')
    
    if not pending_user_id:
        return JsonResponse({
            'status': 'error',
            'message': 'No pending 2FA login',
        }, status=400)
    
    code = request.POST.get('code', '').strip()
    if not code or len(code) != 6 or not code.isdigit():
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid code format',
        }, status=400)
    
    try:
        user = User.objects.get(id=pending_user_id)
        from .totp_utils import verify_totp
        
        if not verify_totp(user.totp_secret, code):
            # ✅ Code invalide : NE PAS créer la session utilisateur
            # La session 2FA persiste pour laisser l'utilisateur réessayer
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid code',
            }, status=401)
        
        # ✅ Code VALIDE : créer la session utilisateur
        login(request, user)
        
        # ✅ Nettoyer la session 2FA temporaire
        if 'pending_2fa_user_id' in request.session:
            del request.session['pending_2fa_user_id']
        
        return JsonResponse({
            'status': 'success',
            'message': 'Login successful',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
            }
        }, status=200)
    except User.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': 'User not found',
        }, status=401)
    except Exception as e:
        logger.error(f"Verify TOTP login error: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'Verification failed',
        }, status=500)