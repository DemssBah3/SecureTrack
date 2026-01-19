from django.http import JsonResponse
from django.views.decorators.http import require_http_methods


@require_http_methods(["GET"])
def index(request):
    """Root endpoint of the API"""
    return JsonResponse({
        'message': 'Welcome to SecureTrack API',
        'version': '1.0.0',
        'status': 'running'
    })


@require_http_methods(["GET"])
def health_check(request):
    """Health check endpoint for monitoring"""
    return JsonResponse({
        'status': 'healthy',
        'service': 'securetrack'
    })
