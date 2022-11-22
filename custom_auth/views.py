from re import T
from .models import (CustomUser, CustomerProfile,
                        StaffProfile
                        )
from .serializers import (CustomUserSerializers, CustomUserDetailsSerializer, 
                            EmailVerificationSerializer, LoginSerializer, 
                            LogoutSerializer, ResetPasswordEmailRequestSerializer,
                            SetNewPasswordSerializer, VerifyOTPForResetPasswordSerializer,
                            ChangePasswordSerializer, CustomerProfilePictureSerializer, 
                            PhoneOtpSerializer, RequestPrimaryEmailUpdateEmailSerializer,
                            RequestPrimaryPhoneOtpSerializer, LoginOTPRequestSerializer,
                            LoginOTPVerifySerializer, StaffProfileSerializers, PermissionSerializer,
                            StaffUserSerializer, StaffProfilePictureSerializer, StaffUserDetailsSerializer,
                            StaffRoleCreateSerializer, StaffRoleDetailsSerializer
                            )
from rest_framework.views import APIView
from rest_framework.generics import (GenericAPIView, RetrieveUpdateAPIView, 
                                        ListAPIView, ListCreateAPIView, RetrieveUpdateDestroyAPIView)
from rest_framework.response import Response
from rest_framework import status, permissions
from utils.send_email import Util
from django.contrib.sites.shortcuts import get_current_site
from django.shortcuts import get_object_or_404, get_list_or_404
from django.urls import reverse
import jwt
from auth_api import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.exceptions import ValidationError, AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.shortcuts import redirect
from django.http import HttpResponsePermanentRedirect
import os
from .utils import (get_registration_verify_email_data, get_staff_registration_verify_email_data, 
                    structure_role_permissions, get_permissions)
import random
from django.utils import timezone
from .tokens import PrimaryEmailUpdateTokenGenerator, PrimaryPhoneUpdateTokenGenerator
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from .tasks import send_email
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import Permission, Group
import string
from random import *
from utils.permissions import CustomPermission, access_permissions_fields


class CustomRedirect(HttpResponsePermanentRedirect):

    allowed_schemes = [os.environ.get('APP_SCHEME'), 'http', 'https']

class Register(GenericAPIView):
    serializer_class = CustomUserSerializers

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            user_data = serializer.data
            user = CustomUser.objects.get(email=user_data['email']) if user_data['email'] else CustomUser.objects.get(phone_number=user_data['phone_number'])
            data = get_registration_verify_email_data(user, request)
            try:
                kwargs = {'data': data}
                send_email.delay(**kwargs)
                context = {'message': 'registration successfull. For verfiy check email and verfiy. Verify email expired within 30 minutes'}
                return Response(context, status=status.HTTP_201_CREATED)
            except:
                return Response({"message": 'Network Error', 'errors': ['registration successfull but can not send verify email.Please check your internet connection.']}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response({"message": 'Bad Request', 'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)



class SendVerifyEmail(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        if not user.is_verified:
            data = get_registration_verify_email_data(user, request)
            try:
                kwargs = {'data': data}
                send_email.delay(**kwargs)
                context = {'message': 'Verify email send successfully. For verfiy check email and verfiy. Verify email expired within 30 minutes.'}
                return Response(context, status=status.HTTP_200_OK)
            except:
                return Response({"message": 'Network Error', 'errors': ['can not send verify email.Please check your internet connection.']}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response({'message': 'Validation Error', 'errors': ['User Already verified.']})

class VerifyRegisterEmail(APIView):
    serializer_class = EmailVerificationSerializer
    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING
    )

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = CustomUser.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
                return Response({'message': 'Successfully activated.'}, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'You already verified your user.'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            raise ValidationError('Activation expired.')
        except jwt.exceptions.DecodeError as identifier:
            raise ValidationError('Invalid token.')

class LoginView(GenericAPIView):
    serializer_class = LoginSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({"message": 'Bad Request', 'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class LoginOTPRequest(GenericAPIView):
    serializer_class = LoginOTPRequestSerializer
    def post(self, request):
        try:
            email_or_phone = request.data.get('email_or_phone', '')
            if email_or_phone:
                try:
                    user = CustomUser.objects.get(email=email_or_phone)
                    customer_name= user.customer_profile.name
                    data = {}
                    data['email'] = email_or_phone
                    otp = random.sample(range(0, 9), 4)
                    otp = "".join(map(str, otp))
                    data["otp"] = otp
                    data["expired_at"] = timezone.now() + timezone.timedelta(minutes=5)
                    serializer = self.serializer_class(data=data)
                    serializer.is_valid(raise_exception=True)
                    serializer.save()
                    context_data = f"Hello, {customer_name}, Your login OTP code is {otp}. OTP expire after 5 minutes."
                    data = {'email_body': context_data, 'to_email': email_or_phone,
                        'email_subject': 'Login OTP'}
                    try:
                        kwargs = {'data': data}
                        send_email.delay(**kwargs)
                        return Response({'message': 'We have sent you login OTP code in your email.', 'data': []}, status=status.HTTP_200_OK)
                    except Exception as e:
                        print('email exception:', e)
                        return Response({"message": 'Network Error', 'errors': ['can not send login OTP email.Please check your internet connection.']}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                except CustomUser.DoesNotExist:
                    try:
                        user=CustomUser.objects.get(phone_number=email_or_phone) 
                        customer_name= user.customer_profile.name
                        data = {}
                        data['phone_number'] = email_or_phone
                        otp = random.sample(range(0, 9), 4)
                        otp = "".join(map(str, otp))
                        data["otp"] = otp
                        data["expired_at"] = timezone.now() + timezone.timedelta(minutes=5)
                        serializer = self.serializer_class(data=data)
                        serializer.is_valid(raise_exception=True)
                        serializer.save()
                        context_data = f"Hello, {customer_name}, Your login OTP code is {otp}. OTP expire after 5 minutes."
                        return Response({'message': context_data, 'data':[]}, status=status.HTTP_200_OK)
                    except CustomUser.DoesNotExist:
                        return Response({'message': 'something wrong', 'errors': ['User does not exit']}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                return Response({'message': 'something wrong', 'errors': ['Invalid json or email_or_phone can not be blank.']}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except CustomUser.DoesNotExist:
            return Response({'message': 'something wrong', 'errors': ['Invalid json or Phone number can not be blank or user does not exit.']}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class LoginWithOTP(GenericAPIView):
    serializer_class = LoginOTPVerifySerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class LogoutView(GenericAPIView):
    serializer_class = LogoutSerializer

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Successfully logout.', 'data': []},status=status.HTTP_204_NO_CONTENT)
        else:
            return Response({"message": 'Bad Request', 'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class RequestPasswordResetEmail(GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            email = request.data.get('email', '')
            user = CustomUser.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(
                    request=request).domain
            relativeLink = reverse(
                    'password_reset_confirm_for_email', kwargs={'uidb64': uidb64, 'token': token})

            redirect_url = request.data.get('redirect_url', '')
            absurl = 'http://'+current_site + relativeLink
            email_body = 'Hello, \n Use link below to reset your password  \n' + \
                    absurl+"?redirect_url="+redirect_url
            data = {'email_body': email_body, 'to_email': user.email,
                        'email_subject': 'Reset your passsword'}
            try:
                kwargs = {'data': data}
                send_email.delay(**kwargs)
                return Response({'message': 'We have sent you a link to reset your password', 'data': []}, status=status.HTTP_200_OK)
            except:
                return Response({"message": 'Network Error', 'errors': ['can not send verify email.Please check your internet connection.']}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except CustomUser.DoesNotExist:
            return Response({'message': 'something wrong', 'errors': ['user does not exit.']}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except:
            raise ValidationError('Invalid json type.')


class PasswordTokenCheckAPIForEmail(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):

        redirect_url = request.GET.get('redirect_url')

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                if len(redirect_url) > 3:
                    return CustomRedirect(redirect_url+'?token_valid=False')
                else:
                    return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')

            if redirect_url and len(redirect_url) > 3:
                return CustomRedirect(redirect_url+'?token_valid=True&message=Credentials Valid&uidb64='+uidb64+'&token='+token)
            else:
                return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')

        except DjangoUnicodeDecodeError as identifier:
            try:
                if not PasswordResetTokenGenerator().check_token(user):
                    return CustomRedirect(redirect_url+'?token_valid=False')
                    
            except UnboundLocalError as e:
                return Response({'message':'UnboundLocalError', 'errors': ['Token is not valid, please request a new one']}, status=status.HTTP_400_BAD_REQUEST)
        except ValueError as e:
            return Response({'message': 'ValueError','errors': ['uidb64 and token is not valid']}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RequestPasswrodResetOTP(GenericAPIView):
    serializer_class = PhoneOtpSerializer
    def post(self, request):
        try:
            phone_number = request.data.get('phone_number', '')
            user = CustomUser.objects.get(phone_number=phone_number)
            customer_name= user.customer_profile.name
            data = {}
            data['phone_number'] = phone_number
            otp = random.sample(range(0, 9), 4)
            otp = "".join(map(str, otp))
            data["otp"] = otp
            data["expired_at"] = timezone.now() + timezone.timedelta(minutes=5)
            serializer = self.serializer_class(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            context_data = f"Hello, {customer_name}, Your reset password verification code is {otp}. OTP expire after 5 minutes."
            return Response({'message': context_data, 'data':[]}, status=status.HTTP_200_OK)

        except CustomUser.DoesNotExist:
            return Response({'message': 'something wrong', 'errors': ['Invalid json or Phone number can not be blank or user does not exit.']}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyOTPForResetPasswrod(GenericAPIView):
    serializer_class = VerifyOTPForResetPasswordSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone_number = serializer.data['phone_number']
        user = CustomUser.objects.get(phone_number=phone_number)
        uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
        token = PasswordResetTokenGenerator().make_token(user)
        context_data = {'uidb64': uidb64, 'token': token}
        return Response({'message': 'OTP verify successfully', 'data': context_data}, status=status.HTTP_200_OK)

class RequestPrimaryEmailUpdateEmail(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = RequestPrimaryEmailUpdateEmailSerializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            user = request.user
            email = request.data.get('email', '')
            redirect_url = request.data.get('redirect_url', '')
            emailb64 = urlsafe_base64_encode(smart_bytes(email))
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PrimaryEmailUpdateTokenGenerator().make_token(user)
            current_site = get_current_site(
                    request=request).domain
            relativeLink = reverse(
                    'primary_email_update_confirm_email', kwargs={'uidb64': uidb64, 'emailb64': emailb64, 'token': token})

            absurl = 'http://'+current_site + relativeLink
            email_body = 'Hello, \n Use link below to reset your primary email  \n' + \
                    absurl+"?redirect_url="+redirect_url
            data = {'email_body': email_body, 'to_email': email,
                        'email_subject': 'Reset your primary email'}
            try:
                kwargs = {'data': data}
                send_email.delay(**kwargs)
                return Response({'message': 'We have sent you a link to reset your primary email', 'data': []}, status=status.HTTP_200_OK)
            except:
                return Response({"message": 'Network Error', 'errors': ['Can not send verify email.Please check your internet connection.']}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        except Exception as e:
            return Response({'message': 'Bad Request', 'errors': [e]}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class PrimaryEmailUpdateTokenCheckAPIForEmail(GenericAPIView):
    def get(self, request, uidb64, emailb64, token):
        redirect_url = request.GET.get('redirect_url')
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            email = smart_str(urlsafe_base64_decode(emailb64))
            user = CustomUser.objects.get(id=id)

            if not PrimaryEmailUpdateTokenGenerator().check_token(user, token):
                if len(redirect_url) > 3:
                    return CustomRedirect(redirect_url+'?token_valid=False')
                else:
                    return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')

            if redirect_url and len(redirect_url) > 3:
                old_email = user.email
                user.email = email
                user.save()
                customer_profile = CustomerProfile.objects.get(user=user)
                customer_profile.email_history.append({'email':old_email})
                customer_profile.save()
                return CustomRedirect(redirect_url)
            else:
                return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')

        except DjangoUnicodeDecodeError as identifier:
            try:
                if not PasswordResetTokenGenerator().check_token(user):
                    return CustomRedirect(redirect_url+'?token_valid=False')
                    
            except UnboundLocalError as e:
                return Response({'message':'UnboundLocalError', 'errors': ['Token is not valid, please request a new one']}, status=status.HTTP_400_BAD_REQUEST)
        except ValueError as e:
            return Response({'message': 'ValueError','errors': ['uidb64 and token is not valid']}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class RequestPrimaryPhoneUpdateOtp(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = RequestPrimaryPhoneOtpSerializer
    def post(self, request):
        try:
            phone_number = request.data.get('phone_number', '')
            user = request.user
            customer_name= user.customer_profile.name
            data = {}
            data['phone_number'] = phone_number
            otp = random.sample(range(0, 9), 4)
            otp = "".join(map(str, otp))
            data["otp"] = otp
            data["expired_at"] = timezone.now() + timezone.timedelta(minutes=5)
            serializer = self.serializer_class(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            context_data = f"Hello, {customer_name}, Your reset phone number verification code is {otp}. OTP expire after 5 minutes."
            return Response({'message': context_data, 'data':[]}, status=status.HTTP_200_OK)

        except CustomUser.DoesNotExist:
            return Response({'message': 'something wrong', 'errors': ['Invalid json or Phone number can not be blank or user does not exit.']}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class VerifyPrimaryPhoneUpdateOtp(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = VerifyOTPForResetPasswordSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone_number = serializer.data['phone_number']
        user = request.user
        old_phone_number = user.phone_number
        user.phone_number = phone_number
        user.save()
        customer_profile = CustomerProfile.objects.get(user=user)
        customer_profile.phone_number_history.append({'phone_number': old_phone_number})
        customer_profile.save()
        return Response({'message': 'OTP verify successfully and primary phone number update successfully', 'data': []}, status=status.HTTP_200_OK)



class ChangePawordFromProfile(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data,context = {'user': request.user})
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Password Change Successfully.', 'data':[]}, status=status.HTTP_200_OK)

class SetNewPasswordAPIView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Password reset success'}, status=status.HTTP_200_OK)





class CustomerProfileView(RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CustomUserDetailsSerializer

    def get_object(self):
        return get_object_or_404(CustomUser, id=self.request.user.id)
    
    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

class CustomerProfilePictureView(RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CustomerProfilePictureSerializer

    def get_object(self):
        return get_object_or_404(CustomerProfile, user=self.request.user)

    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)





class ListCustomerView(ListAPIView):
    queryset = CustomUser.objects.filter(user_type=1)
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CustomUserSerializers


class CustomerCartView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        customer = CustomerProfile.objects.get(user=request.user)
        return Response({'data': customer.in_cart}, status=status.HTTP_200_OK)
    
    def post(self, request):
        try:
            cart_items = request.data['cart_items']
            customer = CustomerProfile.objects.get(user=request.user)
            customer.in_cart = cart_items
            customer.save()
            return Response({'data': customer.in_cart}, status=status.HTTP_200_OK)
        except KeyError as e:
            raise ValidationError('Invalid cart_items json.')
        

class CustomerFavouriteView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        customer = CustomerProfile.objects.get(user=request.user)
        return Response({'data': customer.favourites}, status=status.HTTP_200_OK)
    
    def post(self, request):
        try:
            favourite_items = request.data['favourite_items']
            customer = CustomerProfile.objects.get(user=request.user)
            customer.favourites = favourite_items
            customer.save()
            return Response({'data': customer.favourites}, status=status.HTTP_200_OK)
        except KeyError as e:
            raise ValidationError('Invalid favourite_items json.')

class CustomerHistoryView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        customer = CustomerProfile.objects.get(user=request.user)
        return Response({'data': customer.history}, status=status.HTTP_200_OK)
    
    def post(self, request):
        try:
            history_items = request.data['history_items']
            customer = CustomerProfile.objects.get(user=request.user)
            customer.history = history_items
            customer.save()
            return Response({'data': customer.history}, status=status.HTTP_200_OK)
        except KeyError as e:
            raise ValidationError('Invalid history_items json.')


class SendEmailView(GenericAPIView):
    def post(self,request):
        data = request.data
        subscriber_name = data["subscriber_name"]
        subscriber_email = data["subscriber_email"]
        subscriber_phone = data["subscriber_phone"]
        subscriber_message = data["subscriber_query"]

        html_content = render_to_string('email_template.html', 
            {'subscriber_name': subscriber_name, 
            'subscriber_email': subscriber_email, 
            'subscriber_phone': subscriber_phone, 
            'subscriber_message': subscriber_message}
            )
        text_content = strip_tags(html_content)

        data = {
            "email_body": text_content,
            "to_email": "rabbi@adnanfoundation.com",
            "email_subject": "From AGL Authentication",
        }
        Util.send_email_with_template(html_content, data)
        
        return Response("ding dong", status=status.HTTP_200_OK)



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
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({'message': 'Group/Role Delete Successfully!'},status=status.HTTP_204_NO_CONTENT)




class StaffRoleListView(GenericAPIView):
    # permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser, CustomPermission]
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
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser, CustomPermission]
    serializer_class = StaffUserDetailsSerializer
    perm_slug = "custom_auth.staffprofile"
    def get_object(self):
        return get_object_or_404(CustomUser, id=self.request.user.id)
    
    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        # print(Permission.objects.filter(group__user=request.user))
        fields = access_permissions_fields(request, self.perm_slug)
        print('access fields:',fields)
        instance = self.get_object()
        serializer = self.get_serializer(instance)
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


    

