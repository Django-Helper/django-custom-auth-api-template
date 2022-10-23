import email
from lib2to3.pgen2 import token
from signal import raise_signal
from django.shortcuts import render
from .models import CustomUser, CustomerProfile
from .serializers import (CustomUserSerializers, CustomUserDetailsSerializer, 
                            EmailVerificationSerializer, LoginSerializer, 
                            LogoutSerializer, ResetPasswordEmailOrPhoneRequestSerializer,
                            SetNewPasswordSerializer)
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView, RetrieveUpdateAPIView, ListAPIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework_simplejwt.tokens import RefreshToken
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


class CustomRedirect(HttpResponsePermanentRedirect):

    allowed_schemes = [os.environ.get('APP_SCHEME'), 'http', 'https']

class Register(GenericAPIView):
    serializer_class = CustomUserSerializers

    def post(self, request):
        if 'user_type' in request.data:
            user_type = request.data['user_type']
            if user_type == 'customer':
                user_type = 1
            elif user_type == 'admin':
                user_type = 2
            else:
                user_type = 3
            request.data['user_type'] = user_type

        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()

            user_data = serializer.data
            user = CustomUser.objects.get(email=user_data['email']) if user_data['email'] else CustomUser.objects.get(phone_number=user_data['phone_number'])
            token = RefreshToken.for_user(user)
            current_site = get_current_site(request).domain
            relativeLink = reverse('register_email_verify')
            absurl = 'http://'+current_site+relativeLink+'?token='+str(token)
            email_body = 'Hi '+user.username+' Use link below to verify your email \n'+absurl
            data = {'email_body':email_body, 'to_email': user.email, 'email_subject': 'Verify your email'}
            Util.send_email(data)
            context = {'data': 'registration successfull. For verfiy check email and verfiy.'}
            return Response(context, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SendVerifyEmail(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        token = RefreshToken.for_user(user)
        current_site = get_current_site(request).domain
        relativeLink = reverse('register_email_verify')
        absurl = 'http://'+current_site+relativeLink+'?token='+str(token)
        email_body = 'Hi '+user.username+' Use link below to verify your email \n'+absurl
        data = {'email_body':email_body, 'to_email': user.email, 'email_subject': 'Verify your email'}
        Util.send_email(data)
        context = {'data': 'Verify email send successfully. For verfiy check email and verfiy.'}
        return Response(context, status=status.HTTP_200_OK)

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
            return Response({'email': 'Successfully activated.'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            raise ValidationError('Activation expired.')
        except jwt.exceptions.DecodeError as identifier:
            raise ValidationError('Invalid token.')

class LoginView(GenericAPIView):
    serializer_class = LoginSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class LogoutView(GenericAPIView):
    serializer_class = LogoutSerializer

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({'message': 'Successfully logout.'},status=status.HTTP_204_NO_CONTENT)


class RequestPasswordResetEmailOrPhoneOTP(GenericAPIView):
    serializer_class = ResetPasswordEmailOrPhoneRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email_or_phone = request.data.get('email_or_phone', '')

        if CustomUser.objects.filter(email=email_or_phone).exists():
            user = CustomUser.objects.get(email=email_or_phone)
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
            Util.send_email(data)
        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


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
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTP(GenericAPIView):
    pass

class ChangePawordFromProfile(GenericAPIView):
    pass

class SetNewPasswordAPIView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)





class CustomerProfileView(RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CustomUserDetailsSerializer
    lookup_field = 'username'

    def get_object(self):
        username = self.kwargs['username']
        return get_object_or_404(CustomUser, username=username)
    
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

