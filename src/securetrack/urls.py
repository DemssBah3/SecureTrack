from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from core import views as core_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', core_views.index, name='index'),

    # ✅ Auth routes: /auth/signup/, /auth/login/, etc.
    path('auth/', include('accounts.urls', namespace='accounts')),

    # ✅ Core routes: /api/, /api/health/
    path('api/', include('core.urls', namespace='core')),

    # ✅ Tickets routes: /api/tickets/...
    path('api/tickets/', include('tickets.urls', namespace='tickets')),
]

# Servir fichiers statiques et media en développement
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
