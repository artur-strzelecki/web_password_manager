from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken

# device


def get_device_2f(user, confirmed=True):
    devices = devices_for_user(user, confirmed=confirmed)
    for device in devices:
        if isinstance(device, TOTPDevice):
            return device


def create_device_2f(user):
    device = get_device_2f(user)
    if not device:
        device = user.totpdevice_set.create(confirmed=False)
        # create static device (emergency codes)
        create_emergency_device_2f(user)
    else:
        device = None

    return device


def verify_device_2f(user, token):
    veryf = False
    device = get_device_2f(user, False)
    if device is not None and device.verify_token(token):
        if not device.confirmed:
            device.confirmed = True
            device.save()
            # create emergency codes after confirmed totp device
            create_tokens_emergency_2f(user)
            veryf = True

    return veryf


def delete_device_2f(user, confirmed=True):
    devices = devices_for_user(user, confirmed=confirmed)
    for device in devices:
        device.delete()


# user

def veryf_user_2f(user, token):
    veryf = False
    device = get_device_2f(user)
    if device is not None and device.verify_token(token):
        veryf = True

    return veryf


def veryf_user_emergency_f2(user, token):
    veryf = False
    device = get_user_emergency_device_2f(user)
    if device is not None and device.verify_token(token):
        veryf = True

    return veryf


# emergency code
def get_user_emergency_device_2f(user):
    devices = devices_for_user(user, confirmed=True)
    for device in devices:
        if isinstance(device, StaticDevice):
            return device


def create_emergency_device_2f(user):
    device = get_user_emergency_device_2f(user)
    if not device:
        device = StaticDevice.objects.create(user=user, name="Emegrency")


def create_tokens_emergency_2f(user):
    device = get_user_emergency_device_2f(user)
    if device:
        # delete all tokens
        device.token_set.all().delete()

        # create 6 new tokens
        for n in range(6):
            token = StaticToken.random_token()
            device.token_set.create(token=token)


def print_tokens_emergency_2f(user):
    codes = None
    device = get_user_emergency_device_2f(user)
    if device:
        codes = device.token_set.all()
    return codes
