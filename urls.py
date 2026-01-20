"""
Main URL configuration for SecureTrack.
"""
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('core.urls')),       # Health check
    path('auth/', include('auth.urls')),      # Authentication
]
