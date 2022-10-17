from django.shortcuts import render
from .models import CustomUser
from .serializers import CustomUserSerializers
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status


class CustomerRegister(APIView):
    def post(self, request):
        request.data['user_type'] = 2
        print(request.data)
        serializer = CustomUserSerializers(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AdminRegister(APIView):
    def post(self, request):
        request.data['user_type'] = 2
        print(request.data)
        serializer = CustomUserSerializers(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        print(serializer.error_messages, serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
