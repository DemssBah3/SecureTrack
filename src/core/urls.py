from django.urls import path
from . import views

app_name = 'core'

urlpatterns = [
    path('', views.index, name='index'),           # /api/
    path('health/', views.health_check, name='health_check'),  # /api/health/
]
