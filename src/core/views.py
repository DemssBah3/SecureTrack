"""
Core views - health checks et homepage.
"""

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.shortcuts import render


@require_http_methods(["GET"])
def health_check(request):
    """
    Endpoint de vérification que l'app est up.
    Utilisé pour les health checks (Docker, Nginx, monitoring)
    
    GET /api/core/health/
    Retour : {"status": "ok", "message": "SecureTrack is running"}
    """
    return JsonResponse({
        'status': 'ok',
        'message': 'SecureTrack is running',
        'service': 'SecureTrack',
    })


@require_http_methods(["GET"])
def index(request):
    """
    Accueil de l'app - informations générales.
    
    GET /api/core/
    Retour : infos app
    """
    return JsonResponse({
        'app': 'SecureTrack',
        'version': '1.0.0',
        'description': 'Secure ticket management system',
        'status': 'ok',
    })


def custom_404(request, exception):
    """Custom 404 page."""
    return render(request, 'core/404.html', status=404)


def custom_500(request):
    """Custom 500 page."""
    return render(request, 'core/500.html', status=500)
