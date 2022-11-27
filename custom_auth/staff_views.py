import string     
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import Permission, Group

from rest_framework.generics import (GenericAPIView, RetrieveUpdateAPIView, RetrieveUpdateDestroyAPIView)
from rest_framework.response import Response
from rest_framework import status, permissions

from .models import (CustomUser, StaffProfile, )
from .staff_serializers import (StaffProfileSerializers, PermissionSerializer,
                            StaffUserSerializer, StaffProfilePictureSerializer, StaffUserDetailsSerializer,
                            StaffRoleCreateSerializer, StaffRoleDetailsSerializer)
from .utils import (get_staff_registration_verify_email_data, structure_role_permissions, )
from .tasks import send_email
from utils.permissions import CustomPermission, access_permissions_fields




# Staff Admin API View


class CustomContentListViews(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser, CustomPermission]
    serializer_class = PermissionSerializer
    perm_slug = "auth.permission"
    def get(self, request):
        fields = access_permissions_fields(request, self.perm_slug)
        print('access fields:',fields)
        permissions = Permission.objects.filter(content_type__app_label__in=['custom_auth','social_auth','country_app', 'auth']).values('content_type__app_label', 'content_type__model', 'codename')
        results = structure_role_permissions(permissions)
        return Response(results, status=status.HTTP_200_OK)

class StaffRoleCreate(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser, CustomPermission]
    serializer_class = StaffRoleCreateSerializer
    perm_slug = "auth.group"
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

class StaffRoleDetailView(RetrieveUpdateDestroyAPIView):
    queryset = Group.objects.all()
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser, CustomPermission]
    serializer_class = StaffRoleDetailsSerializer
    perm_slug = "auth.group"

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['group_id'] = self.kwargs['pk']
        return context

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({'message': 'Group/Role Delete Successfully!'},status=status.HTTP_204_NO_CONTENT)




class StaffRoleListView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser, CustomPermission]
    perm_slug = "auth.group"
    def get(self, request):
        print('request user:', request.user)
        print('request auth:', request.auth)
        roles = Group.objects.all()
        results = [{'id':role.id, 'name':role.name, 'moduels': structure_role_permissions(role.permissions.all().values('content_type__app_label', 'content_type__model', 'codename'))} for role in roles]
        return Response(results, status=status.HTTP_200_OK)


class CreateStaffUser(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser, CustomPermission]
    serializer_class = StaffUserSerializer
    perm_slug = "custom_auth.customuser"
    def post(self, request):
        characters = string.ascii_letters + string.punctuation  + string.digits
        password =  "".join(choice(characters) for x in range(randint(8, 16)))
        request.data['password'] = password
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            user_data = serializer.data
            user = CustomUser.objects.get(email=user_data['email']) if user_data['email'] else CustomUser.objects.get(phone_number=user_data['phone_number'])

            data = get_staff_registration_verify_email_data(user, password, request)
            try:
                kwargs = {'data': data}
                send_email.delay(**kwargs)
                context = {'message': 'registration successfull. Check verify email and verfiy. Verify email expired within 30 minutes.'}
                return Response(context, status=status.HTTP_201_CREATED)
            except:
                return Response({"message": 'Network Error', 'errors': ['registration successfull but can not send verify email.Please check your internet connection.']}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response({"message": 'Bad Request', 'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)



class StaffProfileView(RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser, CustomPermission]  # CustomPermission
    serializer_class = StaffUserDetailsSerializer
    perm_slug = "custom_auth.customuser"
    def get_object(self):
        return get_object_or_404(CustomUser, id=self.request.user.id)
    
    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        # print(Permission.objects.filter(group__user=request.user))
        fields = access_permissions_fields(request, self.perm_slug)
        print('access fields:',fields)
        instance = self.get_object()
        serializer = self.get_serializer(instance, fields=tuple(fields))
        return Response(serializer.data)

class StaffProfilePictureView(RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser, CustomPermission]
    serializer_class = StaffProfilePictureSerializer
    perm_slug = "auth.staffprofile"
    def get_object(self):
        return get_object_or_404(StaffProfile, user=self.request.user)

    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)


class StaffModulePermissionView(GenericAPIView):

    def get(self, request):
        pass

class StaffModuleAttributePermissionView(GenericAPIView):

    def get(self, request):
        pass