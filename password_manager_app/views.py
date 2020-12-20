from django.shortcuts import render, redirect, get_object_or_404
from .forms import RegisterForm, AddNewAccount
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.http import HttpResponse
import string
import random
from .password_enc import encrypt_password
from .models import Account


# user login and registrtion and logout
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


def check_register_view(request):
    # type 1 username
    # type 2 email
    # type 3 password
    if request.method == 'POST':
        message = ''
        type = request.POST['type']
        if type == '1':
            username = request.POST['username']
            if User.objects.filter(username=username).exists():
                message = 'Username ' + username + ' already exists!'
        if type == '2':
            email = request.POST['email']
            if User.objects.filter(email=email).exists():
                message = 'Email ' + email + ' already exists!'
        if type == '3':
            password1 = request.POST['password1']
            password_conf = request.POST['password2']
            if password_conf != password1:
                message = 'Password diffrent!'
        return HttpResponse(message)
    else:
        return HttpResponse('')


def logout_success_view(request):
    return render(request, 'logout_success.html')

# end login and registrtion and logout


# start add new account
def add_new_account_view(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            form = AddNewAccount(request.POST)
            if form.is_valid():
                passw = form.data['password_noenc']
                pass_enc = encrypt_password(request, passw)
                new_form = form.save(commit=False)
                new_form.user = request.user
                new_form.password = pass_enc
                new_form.save()

        return render(request, 'add_new_account.html')
    else:
        return redirect('login')


def take_slide_range_view(request):
    if request.method == 'POST':
        slider_range = request.POST['slider_range']
        chars = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(chars) for i in range(int(slider_range)))  # generate random password
        return HttpResponse(password)
    else:
        return HttpResponse('')


# end add new account

def accounts_view(request):
    if request.user.is_authenticated:
        list_acc = Account.objects.filter(user=request.user)
        if request.method == 'POST':
            search = request.POST.get('search')
            list_search = []
            if search is not None and search != '':
                for acc in list_acc:
                    if search in acc.login or search in acc.website:
                        list_search.append(acc)

                return render(request, 'list_accounts.html', {'list_account': list_search, 'search': search,
                                                              'count_acc': len(list_search)})

        return render(request, 'list_accounts.html', {'list_account': list_acc, 'count_acc': len(list_acc)})
    else:
        return redirect('login')
