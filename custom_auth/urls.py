from django.urls import path
from .views import Register, VerifyRegisterEmail

urlpatterns = [
    path('register/', Register.as_view(), name="register"),
    path('register_email_verify/', VerifyRegisterEmail.as_view(), name='register_email_verify')
]