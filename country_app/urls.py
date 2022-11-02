from django.urls import path
from .views import GroupByCountry
urlpatterns = [
    path('', GroupByCountry.as_view())
]