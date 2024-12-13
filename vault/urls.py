from django.urls import path
from . import views

urlpatterns = [
    path('', views.welcome, name='welcome'),
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('add-password/', views.add_password, name='add_password'),
    path('create-group/', views.create_group, name='create_group'),
    path('logout/', views.user_logout, name='logout'),
    path('edit-group/<str:group_id>/', views.edit_group, name='edit_group'),
        path('verify_account_password/', views.verify_account_password, name='verify_account_password'),


]
