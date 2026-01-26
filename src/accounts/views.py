from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.core.exceptions import ValidationError
from .serializers import SignupSerializer, LoginSerializer, UserSerializer
from .totp_utils import generate_secret, generate_qr_code, verify_totp

User = get_user_model()


@api_view(['POST'])
@permission_classes([AllowAny])
def signup(request):
    """Sign up endpoint"""
    serializer = SignupSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        return Response({'message': 'User created', 'user': UserSerializer(user).data}, status=status.HTTP_201_CREATED)
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
            user = authenticate(request, username=user.username, password=password)
            if user:
                login(request, user)
                if user.totp_enabled:
                    return Response({'message': '2FA required', 'totp_required': True}, status=status.HTTP_200_OK)
                return Response({'message': 'Login successful', 'user': UserSerializer(user).data}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            pass
        
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """Logout endpoint"""
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
    
    secret = generate_secret()  # ✅ FIX: generate_secret
    qr_code = generate_qr_code(request.user.email, secret)
    request.session['totp_secret'] = secret
    
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
        return Response({'error': 'Invalid code'}, status=status.HTTP_401_UNAUTHORIZED)
    
    # ✅ FIXED: Use generate_backup_codes method
    backup_codes = request.user.generate_backup_codes()
    
    request.user.totp_secret = secret
    request.user.totp_enabled = True
    request.user.save()
    
    del request.session['totp_secret']
    
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
        return Response({'error': 'Invalid password'}, status=status.HTTP_401_UNAUTHORIZED)
    
    request.user.totp_enabled = False
    request.user.totp_secret = None
    request.user.save()
    
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
        return Response({'error': 'Invalid code'}, status=status.HTTP_401_UNAUTHORIZED)
    
    login(request, user)
    if 'pending_2fa_user_id' in request.session:
        del request.session['pending_2fa_user_id']
    
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
