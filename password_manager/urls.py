from django.contrib import admin
from django.urls import path
from django.contrib.auth import views as av
from password_manager_app.views import login_view, register_view, accounts_view, check_register_view, \
    logout_success_view, add_new_account_view, take_slide_range_view, edit_account_view, activate_view, \
    profile_user_view, copy_info_view, configure_2f_view, send_email_view
from django.conf import settings
from django.views.generic import TemplateView

urlpatterns = [
    path('admin/', admin.site.urls, name='admin'),
    path('', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('accounts/', accounts_view, name='accounts'),
    path('check_register/', check_register_view, name='check_register'),
    path('logout_success/', logout_success_view, name='logout_success'),
    path('logout/', av.LogoutView.as_view(), {'next_page': settings.LOGOUT_REDIRECT_URL}, name='logout'),
    path('add/', add_new_account_view, name='add_new_account'),
    path('slider_range/', take_slide_range_view, name='take_slider'),
    path('accounts/<int:id>/', edit_account_view, name='edit_account'),
    path('activate/<uidb64>/<token>', activate_view, name='activate'),
    path('profile/', profile_user_view, name='profile'),
    path('reset_password/', av.PasswordResetView.as_view(template_name='forgot_password/reset_password.html'), name='reset_password'),
    path('reset_password_done/', av.PasswordResetDoneView.as_view(template_name='forgot_password/reset_password_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', av.PasswordResetConfirmView.as_view(template_name='forgot_password/reset_token.html'), name='password_reset_confirm'),
    path('reset_password_complete/', av.PasswordResetCompleteView.as_view(template_name='forgot_password/reset_password_complete.html'), name='password_reset_complete'),
    path('profile/change_password', av.PasswordChangeView.as_view(template_name='change_password/change_password.html'), name='password_change'),
    path('profile/change_password_done', av.PasswordChangeDoneView.as_view(template_name='change_password/change_password_done.html'), name='password_change_done'),
    path('copy_info_acc/', copy_info_view, name='copy_info_acc'),
    path('configure_two_factor/', configure_2f_view, name='configure_two_factor'),
    path('send_email/', send_email_view, name='send_email'),
    path('send_email_done/', TemplateView.as_view(template_name='send_email_done.html'), name='send_email_done')

]
