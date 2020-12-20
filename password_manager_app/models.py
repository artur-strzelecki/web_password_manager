from django.db import models
from django.contrib.auth.models import User


class Account(models.Model):
    password = models.BinaryField()
    login = models.TextField(blank=False)
    website = models.TextField(blank=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    range = models.IntegerField()

