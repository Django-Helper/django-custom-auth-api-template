import uuid
from django.db import models
from django.contrib.auth.models import (AbstractBaseUser, PermissionsMixin, Permission)
from django.utils.translation import gettext_lazy as _
from custom_auth.managers import CustomUserManager
from rest_framework_simplejwt.tokens import RefreshToken

# Create your models here.

class CustomUser(AbstractBaseUser, PermissionsMixin):
    USER_TYPE_CHOICES = (
        (1, 'customer'),
        (2, 'staff'),
        (3, 'super admin'),
    )

    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, unique=True)

    email = models.EmailField(
        _('email address'), unique=True, blank=True, null=True)
    phone_number = models.CharField(
        max_length=16, unique=True, blank=True, null=True)
    username = models.CharField(max_length=255, unique=True, db_index=True)

    user_type = models.PositiveSmallIntegerField(choices=USER_TYPE_CHOICES, blank=True, null=True)
    auth_providers = models.JSONField(default=list)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'

    REQUIRED_FIELDS = ['username']

    objects = CustomUserManager()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.username
    
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }

    class Meta:
        permissions = (
            ('can_view_customuser__email', 'Can view StaffProfile email'),
            ('can_change_customuser__email', 'Can change customuser email'),
            ('can_view_customuser__phone_number', 'Can view customuser phone_number'),
            ('can_change_customuser__phone_number', 'Can change customuser phone_number'),
            ('can_view_customuser__username', 'Can view customuser username'),
            ('can_change_customuser__username', 'Can change customuser username'),
            ('can_view_customuser__staff_profile', 'Can view customuser staff_profile'),
            ('can_change_customuser__staff_profile', 'Can change customuser staff_profile'),
            ('can_view_customuser__customer_profile', 'Can view customuser customer_profile'),
            ('can_change_customuser__customer_profile', 'Can change customuser customer_profile'),
        )



class StaffProfile(models.Model):
    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, unique=True)

    user = models.OneToOneField(CustomUser, related_name = 'staff_profile',
        on_delete=models.CASCADE, blank=True)
    name = models.CharField(max_length=255, blank=False, null=False, db_index=True)
    address = models.CharField(max_length=255, blank=True)
    postal_code = models.CharField(max_length=255, blank=True)
    country = models.CharField(max_length=255, blank=True)
    profile_picture = models.ImageField(upload_to='upload/staff_profile_picture/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        permissions = (
            ('can_view_staffprofile__name', 'Can view StaffProfile name'),
            ('can_change_staffprofile__name', 'Can change staffprofile name'),
            ('can_view_staffprofile__address', 'Can view staffprofile address'),
            ('can_change_staffprofile__address', 'Can change staffprofile address'),
            ('can_view_staffprofile__postal_code', 'Can view staffprofile postal_code'),
            ('can_change_staffprofile__postal_code', 'Can change staffprofile postal_code'),
            ('can_view_staffprofile__country', 'Can view staffprofile country'),
            ('can_change_staffprofile__country', 'Can change staffprofile country'),
            ('can_view_staffprofile__profile_picture', 'Can view staffprofile profile_picture'),
            ('can_change_staffprofile__profile_picture', 'Can change staffprofile profile_picture'),
        )

    def __str__(self) -> str:
        return self.user.email


    

class CustomerProfile(models.Model):
    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, unique=True)

    user = models.OneToOneField(CustomUser, related_name = 'customer_profile',
        on_delete=models.CASCADE, blank=True)

    name = models.CharField(max_length=255, blank=False, null=False, db_index=True)
    address = models.CharField(max_length=255, blank=True)
    postal_code = models.CharField(max_length=255, blank=True)
    country = models.CharField(max_length=255, blank=True)
    profile_picture = models.ImageField(upload_to='customer_profile_picture/', blank=True)
    in_cart = models.JSONField(default=list)
    favourites = models.JSONField(default=list)
    save_address = models.JSONField(default=list)
    save_cards = models.JSONField(default=list)
    history = models.JSONField(default=list)
    email_history = models.JSONField(default=list)
    phone_number_history = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    

    def __str__(self) -> str:
        return self.name


class PhoneOtp(models.Model):
    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    phone_number = models.CharField(
        max_length=16, blank=True, null=True, db_index=True)
    email = models.EmailField(_('email address'), db_index=True, blank=True, null=True)
    otp = models.CharField(max_length=4, blank=False, null=False, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expired_at = models.DateTimeField(db_index=True, blank=False, null=False)
    is_used = models.BooleanField(default=False, db_index=True)

    def __str__(self):
        return str(self.otp) if self.otp else "otp is none"

    
