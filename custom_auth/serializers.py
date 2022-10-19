from dataclasses import fields
import email
import imp
from pyexpat import model
from statistics import mode
from rest_framework import serializers
from .models import CustomUser, CustomerProfile, AdminProfile, AdminRole
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError


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


class CustomUserSerializers(serializers.ModelSerializer):
    customer_profile = CustomerProfileSerializers(required = False)
    admin_profile = AdminProfileSerializers(required = False)
    password = serializers.CharField(
        max_length=68, min_length=8, write_only=True)


    class Meta:
        model = CustomUser
        fields = ['email', 'phone_number', 'username', 'password', 'user_type', 'customer_profile', 'admin_profile']

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
        if user_type == 1:
            CustomerProfile.objects.create(user=user, **customer_profile_data)
        else:
            AdminProfile.objects.create(user=user, **admin_profile_data)
        return user

    def update(self, instance, validated_data):
        if 'customer_profile' in validated_data:
            customer_profile_serializer = self.fields['customer_profile']
            customer_profile = instance.customer_profile
            customer_profile_data = validated_data.pop('customer_profile')
            customer_profile_serializer.update(customer_profile, customer_profile_data)
            return super(CustomerProfileSerializers, self).update(instance, validated_data)
        if 'admin_profile' in validated_data:
            admin_profile_serializer = self.fields['admin_profile']
            admin_profile = instance.admin_profile
            admin_profile_data = validated_data.pop('admin_profile')
            admin_profile_serializer.update(admin_profile, admin_profile_data)
            return super(AdminProfileSerializers, self).update(instance, validated_data)



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
        fields = ['email', 'username', 'phone_number', 'password', 'is_verified', 'tokens']

    
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


# class CustomerCartSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = CustomerProfile
#         fields = ['in_cart']
    
#     def validate(self, attrs):
#         in_cart = attrs['in_cart']
#         if not in_cart:
#             raise serializers.ValidationError('Cart item can not be null.')
#         return attrs