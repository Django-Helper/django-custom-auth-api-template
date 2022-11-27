from django.db.models import Q
from django.contrib.auth.models import Permission, Group
from django.contrib.contenttypes.models import ContentType

from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed, ValidationError

from .models import (CustomUser, StaffProfile, )
from .utils import structure_role_permissions, get_permissions, do_exist_permissions, do_exit_contenttype
from utils.permissions import has_field_permission


class DynamicFieldsModelSerializer(serializers.ModelSerializer):
    """
    A ModelSerializer that takes an additional `fields` argument that
    controls which fields should be displayed.
    """

    def __init__(self, *args, **kwargs):
        # Don't pass the 'fields' arg up to the superclass
        fields = kwargs.pop('fields', None)

        # Instantiate the superclass normally
        super().__init__(*args, **kwargs)

        if fields is not None:
            # Drop any fields that are not specified in the `fields` argument.
            allowed = set(fields)
            existing = set(self.fields)
            for field_name in existing - allowed:
                self.fields.pop(field_name)


class StaffProfileSerializers(serializers.ModelSerializer):
    class Meta:
        model = StaffProfile
        fields = '__all__'


class ContentTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContentType
        fields = '__all__'

class PermissionSerializer(serializers.ModelSerializer):
    content_type = ContentTypeSerializer()
    class Meta:
        model = Permission
        fields = '__all__'


class StaffRoleCreateSerializer(serializers.Serializer):
    id = serializers.UUIDField(required=False, read_only=True)
    name = serializers.CharField(required=True)
    permissions = serializers.JSONField(required=True, write_only=True)
    modules = serializers.JSONField(required=False, read_only=True)

    class Meta:
        fields = '__all__'

    def validate_permissions(self, value):
        if not all('codename' in item and 'content_type__app_label' in item for item in value):
            raise serializers.ValidationError("Permissions object key is not valid. Permissions object only have 'codename' and 'content_type__app_label' key!")
        codenames = list(set([item['codename'] for item in value]))
        content_type__app_labels = list(set([item['content_type__app_label'] for item in value]))
        do_exit_contenttype(content_type__app_labels)
        do_exist_permissions(codenames)
        return value
    
    def validate_name(self, value):
        try:
            Group.objects.get(name=value.lower())
        except:
            return value
        else:
            raise serializers.ValidationError(f'{value} group/role already exist!')
    
    def create(self, validated_data):
        name = validated_data.pop('name')
        permission_objts = validated_data.pop('permissions')
        new_group, created = Group.objects.get_or_create(name=name.lower())
        if permission_objts:
            codenames = [item['codename'] for item in permission_objts]
            content_type__app_labels = [item['content_type__app_label'] for item in permission_objts]
            permissions = Permission.objects.filter(Q(codename__in=codenames) & Q(content_type__app_label__in=content_type__app_labels))
            new_group.permissions.set(permissions)   
        new_group.save()
        validated_data['id'] = new_group.id
        validated_data['name'] = new_group.name
        validated_data['modules'] = structure_role_permissions(new_group.permissions.all().values('content_type__app_label', 'content_type__model', 'codename'))
        return validated_data


class StaffRoleDetailsSerializer(serializers.ModelSerializer):
    permissions = serializers.JSONField(required=False, write_only=True)
    modules = serializers.JSONField(read_only=True)
    remove_permissions = serializers.JSONField(required=False,write_only=True)
    name = serializers.CharField(required=False)

    class Meta:
        model = Group
        fields = ['id', 'name', 'permissions', 'modules', 'remove_permissions']
    
    def validate_name(self, value):
        try:
            group=Group.objects.get(name=value.lower())
        except:
            return value
        else:
            if group.id == self.context['group_id']:
                return value
            raise serializers.ValidationError(f'{value} group/role already exist!')


    def validate_permissions(self, value):
        if not all('codename' in item and 'content_type__app_label' in item for item in value):
            raise serializers.ValidationError("Permissions object key is not valid. Permissions object only have 'codename' and 'content_type__app_label' key!")
        codenames = list(set([item['codename'] for item in value]))
        content_type__app_labels = list(set([item['content_type__app_label'] for item in value]))
        do_exit_contenttype(content_type__app_labels)
        do_exist_permissions(codenames)
        return value

    def validate_remove_permissions(self, value):
        if not all('codename' in item and 'content_type__app_label' in item for item in value):
            raise serializers.ValidationError("Revmoe_Permissions object key is not valid. Revmoe_Permissions object only have 'codename' and 'content_type__app_label' key!")
        codenames = list(set([item['codename'] for item in value]))
        content_type__app_labels = list(set([item['content_type__app_label'] for item in value]))
        do_exit_contenttype(content_type__app_labels)
        do_exist_permissions(codenames)
        return value

    def update(self, instance, validated_data):
        # print('update role:', validated_data)
        name = validated_data.pop('name') if 'name' in validated_data else None
        new_permissions = validated_data.pop('permissions') if 'permissions' in validated_data else None
        remove_permissions = validated_data.pop('remove_permissions') if 'remove_permissions' in validated_data else None
        if name:
            instance.name = name.lower()
        if remove_permissions:
            permissions = get_permissions(remove_permissions)
            for permission in permissions:
                instance.permissions.remove(permission)
        if new_permissions:
            permissions = get_permissions(new_permissions)
            for permission in permissions:
                instance.permissions.add(permission)
        instance.save()
        validated_data['id'] = instance.id
        validated_data['name'] = instance.name
        validated_data['modules'] = structure_role_permissions(instance.permissions.all().values('content_type__app_label', 'content_type__model', 'codename'))
        return validated_data


class StaffUserDetailsSerializer(DynamicFieldsModelSerializer):
    staff_profile = StaffProfileSerializers(required = False)
    email = serializers.EmailField(required=False) # read_only=True
    phone_number = serializers.CharField(required=False) # read_only=True
    is_verified = serializers.BooleanField(read_only=True)
    roles = serializers.ListField(required=False,write_only=True)
    username = serializers.CharField(required=False)
    class Meta:
        model = CustomUser
        fields = ['email', 'phone_number', 'username', 'is_verified', 'roles', 'groups', 'staff_profile']

    def validate_roles(self, value):
        for role in value:
            # print('role:', role)
            try:
                Group.objects.get(name=role.lower())
            except:
                raise serializers.ValidationError(f'Role {role} does not exit.') 
        return value

    def validate_email(self, value):
        request = self.context['request']
        if has_field_permission(request, 'custom_auth', 'cusotmuser', 'email'):
            return value
        else:
            raise serializers.ValidationError(f'{request.user} does not has permission to update email.')
    
    def validate_phone_number(self, value):
        request = self.context['request']
        if has_field_permission(request, 'custom_auth', 'cusotmuser', 'phone_number'):
            return value
        else:
            raise serializers.ValidationError(f'{request.user} does not has permission to update phone_number.')
    
    def validate_username(self, value):
        request = self.context['request']
        if has_field_permission(request, 'custom_auth', 'cusotmuser', 'username'):
            return value
        else:
            raise serializers.ValidationError(f'{request.user} does not has permission to update username.')

    def validate_staff_profile(self, value):
        request = self.context['request']
        if has_field_permission(request, 'custom_auth', 'cusotmuser', 'staff_profile'):
            return value
        else:
            raise serializers.ValidationError(f'{request.user} does not has permission to update staff_profile.')

    def validate_customer_profile(self, value):
        request = self.context['request']
        if has_field_permission(request, 'custom_auth', 'cusotmuser', 'customer_profile'):
            return value
        else:
            raise serializers.ValidationError(f'{request.user} does not has permission to update customer_profile.')
    
    def update(self, instance, validated_data):
        roles = validated_data.pop('roles') if 'roles' in validated_data else None
        staff_profile_serializer = self.fields['staff_profile']
        staff_profile = instance.staff_profile
        staff_profile_data = validated_data.pop('staff_profile') if 'staff_profile' in validated_data else None
        if staff_profile_data:
            staff_profile_serializer.update(staff_profile, staff_profile_data)
        if roles:
            for role in roles:
                group = Group.objects.get(name=role.lower())
                group.user_set.add(instance)
                group.save()
        return super().update(instance, validated_data)

class StaffProfilePictureSerializer(serializers.ModelSerializer):
    class Meta:
        model = StaffProfile
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

class StaffUserSerializer(serializers.ModelSerializer):
    staff_profile = StaffProfileSerializers(required = False)
    password = serializers.CharField(
        max_length=68, min_length=8, write_only=True)
    
    roles = serializers.ListField(required = True, write_only=True)

    class Meta:
        model = CustomUser
        fields = ['email', 'phone_number', 'username', 'password', 'roles', 'auth_providers', 'staff_profile']

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError('Password length must be 8 or more.')
        return value

    def validate_roles(self, value):
        for role in value:
            # print('role:', role)
            try:
                Group.objects.get(name=role.lower())
            except:
                raise serializers.ValidationError(f'Role {role} does not exit.') 
        return value
    
    def create(self, validated_data):
        roles = validated_data.pop('roles')
        staff_profile_data = validated_data.pop('staff_profile') if 'staff_profile' in validated_data else None
        user = CustomUser.objects.create_staffuser(validated_data.pop('email'), validated_data.pop('password'), 
        validated_data.pop('username'), **validated_data)
        user.auth_providers.append('email')
        user.save()
        for role in roles:
            group = Group.objects.get(name=role.lower())
            group.user_set.add(user)
            group.save()
        StaffProfile.objects.create(user=user, **staff_profile_data)
        return user