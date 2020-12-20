from django.contrib import admin
from django.urls import path
from password_manager_app.views import login_view, register_view, accounts_view, check_register_view

urlpatterns = [
    path('admin/', admin.site.urls, name='admin'),
    path('', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('accounts/', accounts_view, name='accounts'),
    path('check_register/', check_register_view, name='check_register'),
]
