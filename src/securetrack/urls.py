from django.urls import path, include
from . import views

urlpatterns = [
    path('api/', include([
        path('', views.index, name='index'),
        path('health/', views.health_check, name='health_check'),
    ])),
]
