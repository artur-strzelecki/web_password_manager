from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from .forms import RegisterForm


def login_view(request):
    if not request.user.is_authenticated:
        message = ''
        if request.method == 'POST':
            user = authenticate(request, username=request.POST['username'], password=request.POST['password'])
            if user is not None:
                login(request, user)
                return redirect('accounts')
            else:
                # check activate
                try:
                    user = User.objects.get(username=request.POST['username'])
                except User.DoesNotExist:
                    user = None

                if user is not None:
                    if user.is_active is False:
                        message = 'Please check your email and activate your account'
                else:
                    message = 'Incorrect password or username'

        return render(request, 'login.html', {'message': message})
    else:
        return redirect('accounts')


def register_view(request):
    exec_modal_error = 0
    exec_modal_success = 0
    if request.method == 'POST':
        save = 1
        form = RegisterForm(request.POST)
        username = form.data['username']
        password1 = form.data['password1']
        password2 = form.data['password2']
        email = form.data['email']

        # check again before create user
        if User.objects.filter(username=username).exists() or username == '':
            save = 0

        if User.objects.filter(email=email).exists() or email == '':
            save = 0

        if password1 != password2 or password1 == '' or password2 == '':
            save = 0

        if save == 1:
            user = User.objects.create_user(username=username, email=email, password=password1)
            exec_modal_success = 1
        else:
            exec_modal_error = 1

    return render(request, 'register.html', {'exec_modal_error': exec_modal_error,
                                             'exec_modal_success': exec_modal_success})


def accounts_view(request):
    pass