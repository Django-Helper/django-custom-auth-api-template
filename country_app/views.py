from unicodedata import name
from unittest import result
from django.shortcuts import render
from rest_framework.generics import GenericAPIView
from .models import Country,City
from rest_framework.response import Response
from rest_framework import status
from django.db.models import OuterRef, Subquery
# Create your views here.


class GroupByCountry(GenericAPIView):

    def get(self, request):
        # data = [
        #     {
        #         'name': 'Bangladesh',
        #         'cities': ['dhaka','shyelet','barishal']
        #     },
        #     {
        #         'name': 'India',
        #         'cities': ['A','B','C','D','E','F']
        #     }
        # ]

        # for i in data:
        #     country = Country.objects.create(name=i['name'])
        #     for c in i['cities']:
        #         City.objects.create(country=country,name=c)
        result = Country.objects.prefetch_related('city_set').all()
        for r in result:
            print(r.name)
            for c in r.city_set.all():
                print(c.name)
        return Response({'message': 'success'}, status=status.HTTP_200_OK)