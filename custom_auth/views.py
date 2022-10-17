from django.shortcuts import render
from .models import CustomUser
from .serializers import CustomUserSerializers
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from utils.custom_render import CustomRenderer


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
            context = {'data': 'registration successfull. For verfiy check email and verfiy.'}
            return Response(context, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

