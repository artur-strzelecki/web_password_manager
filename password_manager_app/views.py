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
from django.core.paginator import Paginator
from .two_factor_auth import get_device_2f, veryf_user_2f, delete_device_2f, create_device_2f, verify_device_2f, \
    veryf_user_emergency_f2, print_tokens_emergency_2f, create_tokens_emergency_2f
import qrcode
from io import BytesIO
import base64


# user login and registrtion and logout
def login_view(request):
    if not request.user.is_authenticated:
        message = ''
        if request.method == 'POST':
            user = authenticate(request, username=request.POST['username'], password=request.POST['password'])
            if user is not None:
                # two factor auth
                token = request.POST.get('token')
                emergency_code = request.POST.get('emergency_code')

                # uncover input token in template
                if get_device_2f(user) is not None and token is None:
                    return render(request, 'login.html', {'message': message, 'username': request.POST['username'],
                                                          'password': request.POST['password'], '2f': True})

                # veryf token
                if get_device_2f(user) is not None and token is not None:
                    if emergency_code is None:
                        veryf = veryf_user_2f(user, token)
                    else:
                        veryf = veryf_user_emergency_f2(user, token)

                    if veryf is True:
                        login(request, user)
                        return redirect('accounts')
                    else:  # to write token again
                        message = 'Invalid token, please try again'
                        return render(request, 'login.html', {'message': message, 'username': request.POST['username'],
                                                              'password': request.POST['password'], '2f': True})

                # end two factor auth

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

        return render(request, 'login.html', {'message': message, '2f': False})
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

                link_to_email = 'https://' + get_current_site(request).domain + link
                email = EmailMessage(
                    'Activate your account (password manager)',
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
        list_acc = Account.objects.filter(user=request.user).order_by('-id')

        paginator = Paginator(list_acc, 7)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)

        if request.method == 'POST':
            search = request.POST.get('search')
            list_search = []
            if search is not None and search != '':
                for acc in list_acc:
                    if search in acc.login or search in acc.website:
                        list_search.append(acc)

                paginator = Paginator(list_search, 7)
                page_number = request.GET.get('page')
                page_obj = paginator.get_page(page_number)

                return render(request, 'list_accounts.html', {'page': page_obj, 'search': search,
                                                              'count_acc': len(list_search)})

        return render(request, 'list_accounts.html', {'page': page_obj, 'count_acc': len(list_acc)})
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
        # check 2 fator auth

        two_factor_auth = 'Off'
        if get_device_2f(request.user) is not None:
            two_factor_auth = 'On'

        if request.method == 'POST':
            change = 0

            if request.POST.get('submit') is not None:
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

        return render(request, 'profile.html', {'two_factor_auth': two_factor_auth})
    else:
        return redirect('login')
# end profile user


# copy tempalte list account
def copy_info_view(request):
    if request.method == 'POST':
        info = ''
        id_acc = request.POST['id_acc']
        type_copy = request.POST['type_copy']
        account = Account.objects.filter(id=id_acc, user=request.user)

        if type_copy == 'login':
            info = account[0].login

        if type_copy == 'password':
            info = decrypt_password(request, account[0].password)

        return HttpResponse(info)
    else:
        return HttpResponse('')


def configure_2f_view(request):
    if request.user.is_authenticated:
        message = ''
        emergency_codes = None
        configure = 0
        device_true_exists = get_device_2f(request.user, True)  # get only confirmed=True device
        device_false_exists = get_device_2f(request.user, False)  # get only confirmed=False device
        if device_true_exists is None:
            # if false confimed device exists = user during configure
            if device_false_exists is None:
                device = create_device_2f(request.user)  # create confirmed=False device
                device_url = device.config_url
                if device_url is None:
                    message = 'Something goes wrong, please try again later'
            else:
                device = device_false_exists
                device_url = device.config_url
                if device_url is None:
                    message = 'Something goes wrong, please try again later'

            # generate qr code
            qr_code_obj = qrcode.make(device_url)
            bytes_io = BytesIO()
            qr_code_obj.save(bytes_io, format="PNG")
            qr_code = base64.b64encode(bytes_io.getvalue()).decode("utf-8")

            # submit token to confirm device
            if request.method == 'POST':
                veryf = verify_device_2f(request.user, request.POST.get('token'))
                if veryf is True:
                    message = 'Your two-factor authentication is active! This is your emergency codes. Keep it in save place!'
                    emergency_codes_obj = print_tokens_emergency_2f(request.user)
                    configure = 1
                    emergency_codes = []
                    for code in emergency_codes_obj:
                        emergency_codes.append(code.token)

                    device_url = None
                else:
                    message = 'Token incorrect, please try again'
        else:
            if request.method == 'POST':
                if request.POST.get('delete') is not None:
                    delete_device_2f(request.user)
                    return redirect('profile')

                elif request.POST.get('create_emergency_codes') is not None:
                    create_tokens_emergency_2f(request.user)

            message = 'Two-factor authentication already configured'
            configure = 1
            emergency_codes_obj = print_tokens_emergency_2f(request.user)
            emergency_codes = []
            for code in emergency_codes_obj:
                emergency_codes.append(code.token)

            device_url = None
            qr_code = None

        return render(request, 'configure_2f.html', {'device_url': device_url, 'qr_code': qr_code, 'message': message,
                                                     'emergency_codes': emergency_codes, 'configure': configure})
    else:
        return redirect('login')

