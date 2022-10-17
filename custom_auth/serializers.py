from dataclasses import fields
import imp
from pyexpat import model
from statistics import mode
from rest_framework import serializers
from .models import CustomUser, CustomerProfile, AdminProfile, AdminRole


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

    class Meta:
        model = CustomUser
        fields = "__all__"

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError('Password length must be 8 or more.')
        return value
    
    def create(self, validated_data):
        print('custom user:', validated_data)
        customer_profile_data = validated_data.pop('customer_profile')
        if validated_data.get('user_type') == 1:
            user = CustomUser.objects.create_user(validated_data.pop('email'), validated_data.pop('password'), 
            validated_data.pop('user_type'), **validated_data)
        else:
            user = CustomUser.objects.create_superuser(validated_data.pop('email'), validated_data.pop('password'), **validated_data)
        print('user:', user)
        CustomerProfile.objects.create(user=user, **customer_profile_data)
        return user