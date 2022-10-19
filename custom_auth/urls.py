from django.urls import path
from .views import (Register, VerifyRegisterEmail, 
                    LoginView, LogoutView, CustomerCartView, 
                    CustomerFavouriteView, CustomerHistoryView,
                    CustomerProfileView, ListCustomerView)

urlpatterns = [
    path('register/', Register.as_view(), name="register"),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('cart_items/', CustomerCartView.as_view(), name='cart_items'),
    path('favourite_items/', CustomerFavouriteView.as_view(), name='favourite_items'),
    path('user_history/', CustomerHistoryView.as_view(), name='user_history'),
    path('customers/', ListCustomerView.as_view(), name='customers'),
    path('customer_profile/<str:username>', CustomerProfileView.as_view(), name='customer_profile'),
    path('register_email_verify/', VerifyRegisterEmail.as_view(), name='register_email_verify')
]