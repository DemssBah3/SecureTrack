"""
Rate Limiting & Security Middleware for SecureTrack.
OWASP A07:2021 - Identification & Authentication Failures
"""

import time
from django.http import HttpResponse
from django.conf import settings
from django.contrib.auth import get_user_model
from tickets.models import AuditLog

User = get_user_model()


class RateLimitMiddleware:
    """
    Rate limiting middleware pour protéger contre brute-force.
    Limite les tentatives de login à 5 par 15 minutes par IP/user.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        # En-mémoire store pour tracking (en prod, utiliser Redis)
        self.attempts = {}
    
    def __call__(self, request):
        # Appliquer rate limiting seulement sur endpoints sensibles
        if request.path.startswith('/auth/login/'):
            if not self.is_rate_limited(request):
                response = self.get_response(request)
                return response
            else:
                # Trop de tentatives
                return HttpResponse(
                    '{"error": "Too many login attempts. Please try again later."}',
                    status=429,
                    content_type='application/json'
                )
        
        response = self.get_response(request)
        return response
    
    def is_rate_limited(self, request):
        """Vérifier si le user/IP est rate limited"""
        ip = self.get_client_ip(request)
        email = request.POST.get('email', '')
        key = f"{ip}:{email}"
        
        now = time.time()
        period = getattr(settings, 'RATE_LIMIT_PERIOD', 900)  # 15 min
        max_attempts = getattr(settings, 'RATE_LIMIT_ATTEMPTS', 5)
        
        # Nettoyer les anciennes tentatives
        if key in self.attempts:
            self.attempts[key] = [
                t for t in self.attempts[key] 
                if now - t < period
            ]
        else:
            self.attempts[key] = []
        
        # Vérifier si dépassé
        if len(self.attempts[key]) >= max_attempts:
            return True
        
        # Enregistrer cette tentative
        self.attempts[key].append(now)
        return False
    
    def get_client_ip(self, request):
        """Extraire l'IP du client"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class SecurityHeadersMiddleware:
    """
    Ajouter des headers de sécurité supplémentaires.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        
        # ✅ Ajouter headers de sécurité
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        return response
