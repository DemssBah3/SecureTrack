from django.urls import path
from . import views

app_name = 'tickets'

urlpatterns = [
    path('dashboard/', views.dashboard, name='dashboard'),
    path('tickets/', views.ticket_list, name='ticket_list'),
    path('tickets/create/', views.ticket_create, name='ticket_create'),
    path('tickets/<int:ticket_id>/', views.ticket_detail, name='ticket_detail'),
    path('tickets/<int:ticket_id>/edit/', views.ticket_edit, name='ticket_edit'),
    path('tickets/<int:ticket_id>/delete/', views.ticket_delete, name='ticket_delete'),
    path('projects/', views.project_list, name='project_list'),
    path('projects/create/', views.project_create, name='project_create'),
    path('projects/<int:project_id>/', views.project_detail, name='project_detail'),
    path('projects/<int:project_id>/edit/', views.project_edit, name='project_edit'),

    # Member management
    path('projects/<int:project_id>/members/', views.manage_members, name='manage_members'),
    path('projects/<int:project_id>/members/<int:member_id>/role/', views.update_member_role, name='update_member_role'),
    path('projects/<int:project_id>/members/add/', views.add_member, name='add_member'),
    path('projects/<int:project_id>/members/<int:member_id>/remove/', views.remove_member, name='remove_member'),
]
