from django.urls import path
from .views import (Register, VerifyRegisterEmail, 
                    LoginView, LogoutView, CustomerCartView, 
                    CustomerFavouriteView, CustomerHistoryView,
                    CustomerProfileView, ListCustomerView, SendVerifyEmail,
                    RequestPasswordResetEmail, PasswordTokenCheckAPIForEmail,
                    RequestPasswrodResetOTP, SetNewPasswordAPIView, 
                    VerifyOTPForResetPasswrod, ChangePawordFromProfile, 
                    CustomerProfilePictureView, RequestPrimaryEmailUpdateEmail,
                    PrimaryEmailUpdateTokenCheckAPIForEmail,
                    RequestPrimaryPhoneUpdateOtp, VerifyPrimaryPhoneUpdateOtp)
from rest_framework_simplejwt.views import (
    TokenRefreshView
)

urlpatterns = [
    path('register/', Register.as_view(), name="register"),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('send_verify_email/', SendVerifyEmail.as_view(), name='send_verify_email'),
    path('token_refresh/', TokenRefreshView.as_view(), name='toekn_refresh'),
    path('cart_items/', CustomerCartView.as_view(), name='cart_items'),
    path('favourite_items/', CustomerFavouriteView.as_view(), name='favourite_items'),
    path('user_history/', CustomerHistoryView.as_view(), name='user_history'),
    path('customers/', ListCustomerView.as_view(), name='customers'),
    path('customer_profile/', CustomerProfileView.as_view(), name='customer_profile'),
    path('customer_profile_picture/', CustomerProfilePictureView.as_view(), name='customer_profile_picture'),
    path('register_email_verify/', VerifyRegisterEmail.as_view(), name='register_email_verify'),
    path('request_reset_password_email/', RequestPasswordResetEmail.as_view(),
         name="request_reset_password_email"),
    path('password_reset/<uidb64>/<token>/',
         PasswordTokenCheckAPIForEmail.as_view(), name='password_reset_confirm_for_email'),
    path('forgot_password_reset/', SetNewPasswordAPIView.as_view(),
         name='forgot_password_reset'),
    path('request_reset_password_otp/', RequestPasswrodResetOTP.as_view(), name='request_reset_password_otp'),
    path('verify_reset_password_otp/', VerifyOTPForResetPasswrod.as_view(), name='verify_reset_password_otp'),
    path('change_password/', ChangePawordFromProfile.as_view(), name='change_password'),
    path('request_primary_email_update_email/', RequestPrimaryEmailUpdateEmail.as_view(), name='request_primary_email_update_email'),
    path('primary_email_update/<uidb64>/<emailb64>/<token>/', PrimaryEmailUpdateTokenCheckAPIForEmail.as_view(), name='primary_email_update_confirm_email'),
    path('request_primary_phone_update_otp/', RequestPrimaryPhoneUpdateOtp.as_view(), name='request_primary_phone_update_otp'),
    path('verify_primary_phone_update_otp/', VerifyPrimaryPhoneUpdateOtp.as_view(), name='verify_primary_phone_update_otp'),
]