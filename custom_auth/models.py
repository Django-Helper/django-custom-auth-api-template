import email
from enum import unique
import uuid
from django.db import models
from django.contrib.auth.models import (AbstractBaseUser, PermissionsMixin)
from django.utils.translation import gettext_lazy as _
from custom_auth.managers import CustomUserManager

# Create your models here.


class CustomUser(AbstractBaseUser, PermissionsMixin):
    USER_TYPE_CHOICES = (
        (1, 'customer'),
        (2, 'admin')
    )

    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    email = models.EmailField(
        _('email address'), unique=True, blank=True, null=True)
    phone_number = models.CharField(
        max_length=16, unique=True, blank=True, null=True)
    username = models.CharField(max_length=255, unique=True, db_index=True)

    user_type = models.PositiveSmallIntegerField(choices=USER_TYPE_CHOICES)

    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'

    objects = CustomUserManager()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return str(self.email)
