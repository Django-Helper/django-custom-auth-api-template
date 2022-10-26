import email
from email.policy import default
from enum import unique
from unicodedata import name
from unittest.util import _MAX_LENGTH
import uuid
from django.db import models
from django.contrib.auth.models import (AbstractBaseUser, PermissionsMixin)
from django.utils.translation import gettext_lazy as _
from custom_auth.managers import CustomUserManager
from rest_framework_simplejwt.tokens import RefreshToken

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
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }


class AdminRole(models.Model):
    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=255)
    description = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name

class AdminProfile(models.Model):
    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, unique=True)

    user = models.OneToOneField(CustomUser, related_name = 'admin_profile',
        on_delete=models.CASCADE, blank=True)
    name = models.CharField(max_length=255, blank=False, null=False, db_index=True)
    address = models.CharField(max_length=255, blank=True)
    postal_code = models.CharField(max_length=255, blank=True)
    country = models.CharField(max_length=255, blank=True)
    profile_picture = models.ImageField(upload_to='upload/admin_profile_picture/', blank=True, null=True)
    roles = models.ManyToManyField(AdminRole, related_name='admins', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name


    

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


class PhoneOtp(models.Model):
    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    phone_number = models.CharField(
        max_length=16, blank=True, null=True, db_index=True)
    otp = models.CharField(max_length=4, blank=False, null=False, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expired_at = models.DateTimeField(db_index=True, blank=False, null=False)
    is_used = models.BooleanField(default=False, db_index=True)

    def __str__(self):
        return str(self.otp) if self.otp else "otp is none"

    
