from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice

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
    else:
        device = None

    return device


def verify_device_2f(user, token):
    veryf = False
    device = get_device_2f(user, False)
    print(device)
    if device is not None and device.verify_token(token):
        if not device.confirmed:
            device.confirmed = True
            device.save()
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

