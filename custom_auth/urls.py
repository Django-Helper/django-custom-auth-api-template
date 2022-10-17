from django.urls import path
from .views import CustomerRegister, AdminRegister

urlpatterns = [
    path('customer_register/', CustomerRegister.as_view(), name="customer_register"),
    path('admin_register/', AdminRegister.as_view(), name="admin_register")
]