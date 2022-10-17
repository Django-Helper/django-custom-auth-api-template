import email
from email.policy import default
from enum import unique
from unicodedata import name
import uuid
from django.db import models
from django.contrib.auth.models import (AbstractBaseUser, PermissionsMixin)
from django.utils.translation import gettext_lazy as _
from custom_auth.managers import CustomUserManager

# Create your models here.


class CustomUser(AbstractBaseUser, PermissionsMixin):
    USER_TYPE_CHOICES = (
        (1, 'customer'),
        (2, 'admin'),
        (3, 'super admin'),
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

    REQUIRED_FIELDS = ['username']

    objects = CustomUserManager()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.email
    
    def tokens(self):
        return ''


class AdminProfile(models.Model):
    pass

class CustomerProfile(models.Model):
    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, unique=True)

    user = models.OneToOneField(CustomUser, related_name = 'customer_profile',
        on_delete=models.CASCADE, blank=True)

    name = models.CharField(max_length=255, blank=False, null=False, db_index=True)
    address = models.CharField(max_length=255, blank=True)
    postal_code = models.CharField(max_length=255, blank=True)
    country = models.CharField(max_length=255, blank=True)
    profile_picture = models.ImageField(upload_to='upload/customer_profile_picture/', blank=True)
    in_cart = models.JSONField(default=list)
    favourites = models.JSONField(default=list)
    save_address = models.JSONField(default=list)
    save_cards = models.JSONField(default=list)
    history = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name

    
