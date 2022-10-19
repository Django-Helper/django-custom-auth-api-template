import email
from lib2to3.pgen2 import token
from signal import raise_signal
from django.shortcuts import render
from .models import CustomUser, CustomerProfile
from .serializers import CustomUserSerializers, EmailVerificationSerializer, LoginSerializer, LogoutSerializer
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView, RetrieveUpdateAPIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework_simplejwt.tokens import RefreshToken
from utils.send_email import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from auth_api import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.exceptions import ValidationError

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

class CustomerProfileView(RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CustomUserSerializers
    lookup_field = 'username'

    

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

