from django.contrib import admin
from django.urls import path
from password_manager_app.views import login_view, register_view, accounts_view

urlpatterns = [
    path('admin/', admin.site.urls, name='admin'),
    path('', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('accounts/', accounts_view, name='accounts'),
]
