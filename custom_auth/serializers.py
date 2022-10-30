from ast import Delete
from dataclasses import field, fields
import email
from pyexpat import model
from signal import raise_signal
from unittest.util import _MAX_LENGTH
from rest_framework import serializers
from .models import CustomUser, CustomerProfile, AdminProfile, AdminRole, PhoneOtp
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.db.models import Q
from django.utils import timezone
import os
from django.core.validators import validate_email
# from drf_extra_fields.fields import Base64ImageField


class AdminRoleSerializers(serializers.ModelSerializer):
    class Meta:
        model = AdminRole
        fields = '__all__'

class AdminProfileSerializers(serializers.ModelSerializer):
    roles = AdminRoleSerializers(required = False, many = True)
    class Meta:
        model = AdminProfile
        fields = '__all__'

class CustomerProfileSerializers(serializers.ModelSerializer):
    class Meta:
        model = CustomerProfile
        fields = '__all__'

class CustomerProfilePictureSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerProfile
        fields = ['profile_picture']

    def validate(self, attrs):
        if 'profile_picture' not in attrs:
            raise ValidationError('Profile picture can not be blank')
        if attrs['profile_picture'] is None:
            raise ValidationError('Profile picture can not be blank')
        return attrs

    def update(self, instance, validated_data):
        instance.profile_picture.delete(save=True) # delete old profile picture
        return super().update(instance, validated_data)

class CustomUserDetailsSerializer(serializers.ModelSerializer):
    customer_profile = CustomerProfileSerializers(required = False)
    email = serializers.EmailField(read_only=True)
    phone_number = serializers.CharField(read_only=True)
    is_verified = serializers.BooleanField(read_only=True)
    class Meta:
        model = CustomUser
        fields = ['email', 'phone_number', 'username', 'is_verified', 'customer_profile']
    
    def update(self, instance, validated_data):
        customer_profile_serializer = self.fields['customer_profile']
        customer_profile = instance.customer_profile
        customer_profile_data = validated_data.pop('customer_profile')
        customer_profile_serializer.update(customer_profile, customer_profile_data)
        return super().update(instance, validated_data)

class CustomUserSerializers(serializers.ModelSerializer):
    customer_profile = CustomerProfileSerializers(required = False)
    admin_profile = AdminProfileSerializers(required = False)
    password = serializers.CharField(
        max_length=68, min_length=8, write_only=True)


    class Meta:
        model = CustomUser
        fields = ['email', 'phone_number', 'username', 'password', 'user_type', 'auth_providers', 'customer_profile', 'admin_profile']

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError('Password length must be 8 or more.')
        return value
    
    def create(self, validated_data):
        customer_profile_data = validated_data.pop('customer_profile') if 'customer_profile' in validated_data else None
        admin_profile_data = validated_data.pop('admin_profile') if 'admin_profile' in validated_data else None
        user_type = validated_data.pop('user_type')
        if user_type == 3:
            user = CustomUser.objects.create_superuser(validated_data.pop('email'), validated_data.pop('password'), 
            validated_data.pop('username'), **validated_data)
        else:
            user = CustomUser.objects.create_user(validated_data.pop('email'), validated_data.pop('password'), 
            validated_data.pop('username'), user_type, **validated_data)
        user.auth_providers.append('email')
        user.save()
        if user_type == 1:
            CustomerProfile.objects.create(user=user, **customer_profile_data)
        else:
            AdminProfile.objects.create(user=user, **admin_profile_data)
        return user




class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = CustomUser
        fields = ['token']


class LoginSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(
        max_length=255, min_length=3)

    tokens = serializers.SerializerMethodField('get_tokens')

    def get_tokens(self, obj):
        user = CustomUser.objects.get(email=obj['email']) if obj['email'] else CustomUser.objects.get(phone_number=obj['phone_number'])

        return {
            'refresh': user.tokens()['refresh'],
            'access': user.tokens()['access']
        }
    
    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'phone_number', 'password', 'is_verified', 'tokens', 'auth_providers']

    
    def validate(self, attrs):
        email_phone_username = attrs.get('username', '')
        password = attrs.get('password', '')
        # filtered_user_by_email = User.objects.filter(email=email)
        user = auth.authenticate(username=email_phone_username, password=password)

        # if filtered_user_by_email.exists() and filtered_user_by_email[0].auth_provider != 'email':
        #     raise AuthenticationFailed(
        #         detail='Please continue your login using ' + filtered_user_by_email[0].auth_provider)
        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        # if not user.is_verified:
        #     raise AuthenticationFailed('Email is not verified')

        return {
            'email': user.email,
            'phone_number': user.phone_number,
            'username': user.username,
            'is_verified': user.is_verified,
            'providers': user.auth_providers,
            'tokens': user.tokens
        }

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_messages = {
        'bad_token': ('Token is expired or invalid')
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs
    
    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=500, required=True)
    redirect_url = serializers.CharField(max_length=500, required=False)

    class Meta:
        fields = ['email', 'redirect_url']

class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(
        min_length=1, write_only=True)
    uidb64 = serializers.CharField(
        min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()

            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)


class VerifyOTPForResetPasswordSerializer(serializers.Serializer):
    otp = serializers.CharField(min_length=4, max_length=6, write_only=True)
    phone_number = serializers.CharField(read_only = True)
    class Meta:
        fields = ['otp']

    def validate(self, attrs):
        if 'otp' not in attrs:
            raise ValidationError('Otp can not be blank.')
        try:
            time = timezone.localtime()
            otp = PhoneOtp.objects.filter(Q(otp=attrs['otp']) & Q(expired_at__gt=time))[0]
            otp.is_used = True
            otp.save()
            attrs['phone_number'] = otp.phone_number
            PhoneOtp.objects.filter(is_used = True).delete()
        except PhoneOtp.DoesNotExist:
            raise ValidationError('Invalid Otp')
        except IndexError:
            raise ValidationError('Invalid Otp')
        return attrs

class RequestEmailUpdateSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, write_only=True)
    class Meta:
        fields = ['email']
    
    def validate(self, attrs):
        if 'email' not in attrs:
            raise ValidationError('Email field can not be blank')
        if CustomUser.objects.filter(email=attrs['email']).exists():
            raise ValidationError('Email already exist')
        return super().validate(attrs)

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(
        min_length=6, max_length=68, write_only=True)
    new_password = serializers.CharField(
        min_length=6, max_length=68, write_only=True)
    confirm_password = serializers.CharField(
        min_length=6, max_length=68, write_only=True)
    
    class Meta:
        fields = ['old_password', 'new_password', 'confirm_password']

    def validate(self, attrs):
        user = self.context['user']
        print(attrs['new_password'], attrs['confirm_password'])
        if not user.check_password(attrs['old_password']):
            raise ValidationError('Your old password is wrong.')
        if attrs['new_password'] != attrs['confirm_password']:
            raise ValidationError('New Password and confirm passord is not match.')
        if user.check_password(attrs['new_password']):
            raise ValidationError('New password can not be same old password.')
        user.set_password(attrs['confirm_password'])
        user.save()
        return (user)

# class CustomerCartSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = CustomerProfile
#         fields = ['in_cart']
    
#     def validate(self, attrs):
#         in_cart = attrs['in_cart']
#         if not in_cart:
#             raise serializers.ValidationError('Cart item can not be null.')
#         return attrs


class PhoneOtpSerializer(serializers.ModelSerializer):
    class Meta:
        model = PhoneOtp
        fields = '__all__'

    def validate(self, attrs):
        if 'phone_number' not in attrs:
            raise ValidationError('Phone number can not be blank.')
        if PhoneOtp.objects.filter(phone_number=attrs['phone_number']).exists():
            PhoneOtp.objects.filter(phone_number=attrs['phone_number']).delete()
        return super().validate(attrs)


class RequestPrimaryEmailUpdateEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required = True)
    redirect_url = serializers.CharField(required = True)
    class Meta:
        fields = "__all__"
    
    def validate_email(self, value):
        if value is None:
            raise ValidationError('Email can not be blank')
        if CustomUser.objects.filter(email=value).exists():
            raise ValidationError('Email already exist')
        try:
            validate_email(value)
        except ValidationError as e:
            raise ValidationError('Email is not valid')
        else:
            return value
        
    
    def validate_redirect_url(self, value):
        if value is None:
            raise ValidationError('Redirect url can not be blank')
        return value

class RequestPrimaryPhoneOtpSerializer(serializers.ModelSerializer):
    class Meta:
        model = PhoneOtp
        fields = "__all__"

    
    def validate_phone_number(self, value):
        if value is None:
            raise ValidationError('Phone Number can not be blank')
        if CustomUser.objects.filter(phone_number = value).exists():
            raise ValidationError('Phone number already exit')
        if not value.isnumeric():
            raise ValidationError('Invalid Phone number')
        if PhoneOtp.objects.filter(phone_number=value).exists():
            PhoneOtp.objects.filter(phone_number=value).delete()
        return value

class LoginOTPRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = PhoneOtp
        fields = "__all__"

    def validate(self, attrs):
        if 'phone_number' not in attrs and 'email' not in attrs:
            raise ValidationError('Phone number or email can not be blank.')
        if 'phone_number' in attrs:
            if PhoneOtp.objects.filter(phone_number=attrs['phone_number']).exists():
                PhoneOtp.objects.filter(phone_number=attrs['phone_number']).delete()
        if 'email' in attrs:
            if PhoneOtp.objects.filter(email=attrs['email']).exists():
                PhoneOtp.objects.filter(email=attrs['email']).delete()
        return super().validate(attrs)

class LoginOTPVerifySerializer(serializers.ModelSerializer):
    otp = serializers.CharField(min_length=4, max_length=6, write_only=True, required=True)
    username = serializers.CharField(read_only=True)
    email_or_phone = serializers.CharField(write_only = True, required=True)
    class Meta:
        model = CustomUser
        fields = ['otp']
        fields = ['otp', 'email_or_phone' ,'email', 'username', 'phone_number', 'is_verified', 'tokens']

    def validate(self, attrs):
        if 'otp' not in attrs:
            raise ValidationError('Otp can not be blank.')
        if 'email_or_phone' not in attrs:
            raise ValidationError('Email or phone can not be blank')
        try:
            time = timezone.localtime()
            otp = PhoneOtp.objects.filter(Q(otp=attrs['otp']) & Q(expired_at__gt=time) & Q(is_used=False))[0]
            if otp.phone_number and attrs['email_or_phone'].isnumeric():
                try:
                    user = CustomUser.objects.get(phone_number=otp.phone_number)
                    otp.is_used = True
                    otp.save()
                    PhoneOtp.objects.filter(is_used = True).delete()
                    print('login with phone')
                    return {
                        'email': user.email,
                        'phone_number': user.phone_number,
                        'username': user.username,
                        'is_verified': user.is_verified,
                        'tokens': user.tokens
                    }
                except CustomUser.DoesNotExist:
                    raise ValidationError('User does not exit')
            elif otp.email and not attrs['email_or_phone'].isnumeric():
                try:
                    user = CustomUser.objects.get(email=otp.email)
                    otp.is_used = True
                    otp.save()
                    PhoneOtp.objects.filter(is_used = True).delete()
                    print('login with email')
                    return {
                        'email': user.email,
                        'phone_number': user.phone_number,
                        'username': user.username,
                        'is_verified': user.is_verified,
                        'tokens': user.tokens
                    }
                except CustomUser.DoesNotExist:
                    raise ValidationError('User does not exit')
            else:
                raise ValidationError('User does not exit')
        except PhoneOtp.DoesNotExist:
            raise ValidationError('Invalid Otp')
        except IndexError:
            raise ValidationError('Invalid Otp')