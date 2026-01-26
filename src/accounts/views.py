from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.core.exceptions import ValidationError
from .serializers import SignupSerializer, LoginSerializer, UserSerializer
from .totp_utils import generate_secret, generate_qr_code, verify_totp
from tickets.permissions import log_action, get_client_ip

User = get_user_model()


def get_request_ip(request):
    """Extrait l'IP du client (même derrière un proxy)"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


@api_view(['POST'])
@permission_classes([AllowAny])
def signup(request):
    """Sign up endpoint"""
    serializer = SignupSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        
        # ✅ LOG: User created
        log_action(
            user=user,
            action='USER_CREATED',
            resource_type='User',
            resource_id=user.id,
            resource_name=user.username,
            details={'email': user.email},
            ip_address=get_request_ip(request)
        )
        
        return Response(
            {'message': 'User created', 'user': UserSerializer(user).data},
            status=status.HTTP_201_CREATED
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    """Login endpoint"""
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
        # Trouve l'utilisateur par email et authentifie
        try:
            user = User.objects.get(email=email)
            user_auth = authenticate(request, username=user.username, password=password)
            
            if user_auth:
                login(request, user_auth)
                
                # ✅ LOG: Login success
                log_action(
                    user=user_auth,
                    action='LOGIN_SUCCESS',
                    resource_type='User',
                    resource_id=user_auth.id,
                    resource_name=user_auth.username,
                    details={'method': 'password'},
                    ip_address=get_request_ip(request)
                )
                
                if user_auth.totp_enabled:
                    return Response(
                        {'message': '2FA required', 'totp_required': True},
                        status=status.HTTP_200_OK
                    )
                
                return Response(
                    {'message': 'Login successful', 'user': UserSerializer(user_auth).data},
                    status=status.HTTP_200_OK
                )
            else:
                # ✅ LOG: Login failed (wrong password)
                log_action(
                    user=user,
                    action='LOGIN_FAILED',
                    resource_type='User',
                    resource_id=user.id,
                    resource_name=user.username,
                    details={'reason': 'invalid_password'},
                    ip_address=get_request_ip(request)
                )
        
        except User.DoesNotExist:
            # ✅ LOG: Login failed (user not found)
            log_action(
                user=None,
                action='LOGIN_FAILED',
                resource_type='User',
                resource_id=0,
                resource_name=email,
                details={'reason': 'user_not_found', 'email': email},
                ip_address=get_request_ip(request)
            )
        
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """Logout endpoint"""
    user = request.user
    
    # ✅ LOG: Logout
    log_action(
        user=user,
        action='LOGOUT',
        resource_type='User',
        resource_id=user.id,
        resource_name=user.username,
        ip_address=get_request_ip(request)
    )
    
    logout(request)
    return Response({'message': 'Logged out'}, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def me(request):
    """Get current user"""
    serializer = UserSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def setup_2fa(request):
    """Setup 2FA"""
    if request.user.totp_enabled:
        return Response({'error': '2FA already enabled'}, status=status.HTTP_400_BAD_REQUEST)
    
    secret = generate_secret()
    qr_code = generate_qr_code(request.user.email, secret)
    request.session['totp_secret'] = secret
    
    # ✅ LOG: 2FA setup initiated
    log_action(
        user=request.user,
        action='2FA_SETUP_INITIATED',
        resource_type='User',
        resource_id=request.user.id,
        resource_name=request.user.username,
        ip_address=get_request_ip(request)
    )
    
    return Response({
        'secret': secret,
        'qr_code': qr_code,
        'message': 'Scan QR code and verify with code'
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_2fa(request):
    """Verify 2FA code"""
    code = request.data.get('code')
    secret = request.session.get('totp_secret')
    
    if not secret:
        return Response({'error': 'No 2FA setup in progress'}, status=status.HTTP_400_BAD_REQUEST)
    
    if not verify_totp(secret, code):
        # ✅ LOG: 2FA verification failed
        log_action(
            user=request.user,
            action='2FA_VERIFY_FAILED',
            resource_type='User',
            resource_id=request.user.id,
            resource_name=request.user.username,
            details={'reason': 'invalid_code'},
            ip_address=get_request_ip(request)
        )
        
        return Response({'error': 'Invalid code'}, status=status.HTTP_401_UNAUTHORIZED)
    
    # ✅ Generate backup codes
    backup_codes = request.user.generate_backup_codes()
    
    request.user.totp_secret = secret
    request.user.totp_enabled = True
    request.user.save()
    
    del request.session['totp_secret']
    
    # ✅ LOG: 2FA enabled
    log_action(
        user=request.user,
        action='2FA_ENABLED',
        resource_type='User',
        resource_id=request.user.id,
        resource_name=request.user.username,
        details={'backup_codes_generated': len(backup_codes)},
        ip_address=get_request_ip(request)
    )
    
    return Response({
        'message': '2FA enabled',
        'backup_codes': backup_codes
    }, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def disable_2fa(request):
    """Disable 2FA"""
    if not request.user.totp_enabled:
        return Response({'error': '2FA not enabled'}, status=status.HTTP_400_BAD_REQUEST)
    
    password = request.data.get('password')
    if not request.user.check_password(password):
        # ✅ LOG: 2FA disable failed (wrong password)
        log_action(
            user=request.user,
            action='2FA_DISABLE_FAILED',
            resource_type='User',
            resource_id=request.user.id,
            resource_name=request.user.username,
            details={'reason': 'invalid_password'},
            ip_address=get_request_ip(request)
        )
        
        return Response({'error': 'Invalid password'}, status=status.HTTP_401_UNAUTHORIZED)
    
    request.user.totp_enabled = False
    request.user.totp_secret = None
    request.user.save()
    
    # ✅ LOG: 2FA disabled
    log_action(
        user=request.user,
        action='2FA_DISABLED',
        resource_type='User',
        resource_id=request.user.id,
        resource_name=request.user.username,
        ip_address=get_request_ip(request)
    )
    
    return Response({'message': '2FA disabled'}, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_totp_login(request):
    """Verify TOTP during login"""
    code = request.data.get('code')
    user_id = request.session.get('pending_2fa_user_id')
    
    if not user_id:
        return Response({'error': 'No pending 2FA'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_401_UNAUTHORIZED)
    
    if not verify_totp(user.totp_secret, code):
        # ✅ LOG: TOTP verification failed
        log_action(
            user=user,
            action='TOTP_VERIFY_FAILED',
            resource_type='User',
            resource_id=user.id,
            resource_name=user.username,
            details={'reason': 'invalid_code'},
            ip_address=get_request_ip(request)
        )
        
        return Response({'error': 'Invalid code'}, status=status.HTTP_401_UNAUTHORIZED)
    
    login(request, user)
    if 'pending_2fa_user_id' in request.session:
        del request.session['pending_2fa_user_id']
    
    # ✅ LOG: 2FA login success
    log_action(
        user=user,
        action='LOGIN_SUCCESS_2FA',
        resource_type='User',
        resource_id=user.id,
        resource_name=user.username,
        details={'method': '2fa'},
        ip_address=get_request_ip(request)
    )
    
    return Response({
        'message': 'Login successful',
        'user': UserSerializer(user).data
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_backup_codes(request):
    """Get backup codes"""
    if not request.user.totp_enabled:
        return Response({'error': '2FA not enabled'}, status=status.HTTP_400_BAD_REQUEST)
    
    backup_codes = request.user.backup_codes or []
    return Response({'backup_codes': backup_codes}, status=status.HTTP_200_OK)
