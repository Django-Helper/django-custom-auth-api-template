import datetime
import jwt
from auth_api import settings
from django.urls import reverse
from django.contrib.sites.shortcuts import get_current_site

def get_registration_verify_email_data(user, request):
    payload = {
                "user_id": str(user.id),
                "exp": datetime.datetime.utcnow()
                + datetime.timedelta(minutes=5, seconds=00),
                "iat": datetime.datetime.utcnow(),
            }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    # token = RefreshToken.for_user(user).access_token
    current_site = get_current_site(request).domain
    relativeLink = reverse('register_email_verify')
    absurl = 'http://'+current_site+relativeLink+'?token='+str(token)
    email_body = 'Hi '+user.username+' Use link below to verify your email \n'+absurl
    data = {'email_body':email_body, 'to_email': user.email, 'email_subject': 'Verify your email'}
    return data