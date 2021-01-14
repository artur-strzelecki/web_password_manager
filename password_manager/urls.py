from django.contrib import admin
from django.urls import path
from django.contrib.auth.views import LogoutView
from password_manager_app.views import login_view, register_view, accounts_view, check_register_view, \
    logout_success_view, add_new_account_view, take_slide_range_view, edit_account_view, activate_view, \
    profile_user_view
from django.conf import settings

urlpatterns = [
    path('admin/', admin.site.urls, name='admin'),
    path('', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('accounts/', accounts_view, name='accounts'),
    path('check_register/', check_register_view, name='check_register'),
    path('logout_success/', logout_success_view, name='logout_success'),
    path('logout/', LogoutView.as_view(), {'next_page': settings.LOGOUT_REDIRECT_URL}, name='logout'),
    path('add/', add_new_account_view, name='add_new_account'),
    path('slider_range/', take_slide_range_view, name='take_slider'),
    path('accounts/<int:id>/', edit_account_view, name='edit_account'),
    path('activate/<uidb64>/<token>', activate_view, name='activate'),
    path('profile/', profile_user_view, name='profile')
]
