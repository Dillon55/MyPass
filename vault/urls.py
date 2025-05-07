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

    path('edit-password/<str:password_id>/', views.edit_password, name='edit_password'),
    path('decrypt_password/', views.decrypt_password, name='decrypt_password'),
    path('delete-password/', views.delete_password, name='delete_password'),
    path('delete_group/', views.delete_group, name='delete_group'),
    path('verify-2fa/', views.verify_2fa, name='verify_2fa'),
    path('resend-2fa-code/', views.resend_2fa_code, name='resend_2fa_code'),
    path('generate-password/', views.generate_password, name='generate_password'),
    path('cancel-2fa/', views.cancel_2fa, name='cancel_2fa'),

]
