from django.http import JsonResponse
from django.views.decorators.http import require_http_methods


@require_http_methods(["GET"])
def health_check(request):
    """
    Endpoint de vérification que l'app est up.
    Utilisé pour les health checks (Docker, Nginx, monitoring)
    
    GET /api/health/
    Retour : {"status": "ok", "message": "SecureTrack is running"}
    """
    return JsonResponse({
        'status': 'ok',
        'message': 'SecureTrack is running',
    })


@require_http_methods(["GET"])
def index(request):
    """
    Accueil de l'app - informations générales.
    
    GET /api/
    Retour : infos app
    """
    return JsonResponse({
        'app': 'SecureTrack',
        'version': '0.1.0',
        'description': 'Secure ticket management system',
    })
