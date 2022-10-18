from django.urls import path
from .views import Register, VerifyRegisterEmail, LoginView, LogoutView, CustomerCartView

urlpatterns = [
    path('register/', Register.as_view(), name="register"),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('cart/', CustomerCartView.as_view(), name='cart'),
    path('register_email_verify/', VerifyRegisterEmail.as_view(), name='register_email_verify')
]