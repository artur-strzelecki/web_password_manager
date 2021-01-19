from django.shortcuts import render, redirect, get_object_or_404
from .forms import RegisterForm, AddNewAccount
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.http import HttpResponse
from .models import Account
import string
import random
from .password_enc import encrypt_password, decrypt_password
from django.core.mail import EmailMessage
from password_manager.settings import EMAIL_HOST_USER
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from .tokens import activate_token
from django.utils.encoding import force_bytes, force_text


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
                else:
                    message = 'Incorrect password or username'

        return render(request, 'login.html', {'message': message})
    else:
        return redirect('accounts')


def register_view(request):
    create_success = None
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
            create_success = 1
            # send email
            if user is not None:
                user.is_active = False
                user.save()

                link = reverse('activate', kwargs={'uidb64': urlsafe_base64_encode(force_bytes(user.pk)),
                                                   'token': activate_token.make_token(user)})

                link_to_email = 'http://' + get_current_site(request).domain + link
                email = EmailMessage(
                    'Activate your account',
                    'Hello ' + user.username + '!' + '\n' + 'Please click this link to activate your account ' +
                    link_to_email,
                    EMAIL_HOST_USER,
                    [user.email]
                )
                email.send(fail_silently=False)
        else:
            create_success = 0

    return render(request, 'register.html', {'create_success': create_success})


def check_register_view(request):
    # type 1 username
    # type 2 email
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

# start account view
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


def edit_account_view(request, id):
    if request.user.is_authenticated:
        edit = 0
        account = get_object_or_404(Account, pk=id, user=request.user)
        account.password = decrypt_password(request, account.password)
        website_url = account.website
        if 'https://' not in website_url:
            website_url = 'https://' + website_url
        if request.method == 'POST':
            if request.POST.get('submit') is not None:
                form = AddNewAccount(request.POST, instance=account)
                if form.is_valid():
                    passw = form.data['password_noenc']
                    pass_enc = encrypt_password(request, passw)
                    new_form = form.save(commit=False)
                    new_form.password = pass_enc
                    new_form.save()
                    # take info about account again
                    account = get_object_or_404(Account, pk=id, user=request.user)
                    account.password = passw
                    edit = 0
            elif request.POST.get('edit') is not None:
                edit = 1
            elif request.POST.get('delete') is not None:
                account.delete()
                return redirect('accounts')

        return render(request, 'account_edit.html', {'account': account, 'edit': edit, 'website_url': website_url})
    else:
        return redirect('login')

# end account view


# activate account
def activate_view(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and activate_token.check_token(user, token):
        if user.is_active is False:
            user.is_active = True
            user.save()
            message = 'Thank you for your email confirmation. Now you can login your account.'
    else:
        message = 'Activation link is invalid!'

    return render(request, 'activate.html', {'message': message})

# end activate account


# profile user
def profile_user_view(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            change = 0
            # change first name
            if request.POST['first_name'] != '':
                change = 1
                request.user.first_name = request.POST['first_name']
            # change last name
            if request.POST['last_name'] != '':
                change = 1
                request.user.last_name = request.POST['last_name']

            if change == 1:
                request.user.save()

        return render(request, 'profile.html')
    else:
        return redirect('login')
# end profile user