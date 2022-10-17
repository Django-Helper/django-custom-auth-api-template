import email
from lib2to3.pgen2 import token
from django.shortcuts import render
from .models import CustomUser
from .serializers import CustomUserSerializers
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from utils.custom_render import CustomRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from utils.send_email import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from auth_api import settings


class Register(APIView):
    renderer_classes = [CustomRenderer]

    def post(self, request):
        if request.data['user_type'] == 'customer':
            request.data['user_type'] = 1
        elif request.data['user_type'] == 'admin':
            request.data['user_type'] = 2
        else:
            request.data['user_type'] = 3
        serializer = CustomUserSerializers(data=request.data)
        if serializer.is_valid():
            serializer.save()

            user_data = serializer.data
            user = CustomUser.objects.get(id=user_data['id'])
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
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            print(payload)
            user = CustomUser.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Verification expired'}, status=status.HTTP_400_BAD_REQUEST)

