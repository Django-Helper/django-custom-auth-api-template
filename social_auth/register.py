from django.contrib.auth import authenticate
from custom_auth.models import CustomUser
import random
from rest_framework.exceptions import AuthenticationFailed


def generate_username(name):

    username = "".join(name.split(" ")).lower()
    if not CustomUser.objects.filter(username=username).exists():
        return username
    else:
        random_username = username + str(random.randint(0, 1000))
        return generate_username(random_username)


def register_social_user(provider, user_email, user_fullname, user_image):

    try:
        customer = CustomUser.objects.get(email = user_email)
        if provider not in customer.auth_providers:
            customer.auth_providers.append(provider)
            customer.save()
        return {
                    'email': customer.email,
                    'phone_number': customer.phone_number,
                    'username': customer.username,
                    'is_verified': customer.is_verified,
                    'providers': customer.auth_providers,
                    'tokens': customer.tokens(),
                    
                }

    except CustomUser.DoesNotExist:
        social_secret = "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"
        username = generate_username(user_fullname)
        customer = CustomUser.objects.create_user(user_email, social_secret, username, 1)
        customer.is_verified = True
        customer.auth_providers.append(provider)
        customer.save()
        new_user = authenticate(username=user_email, password=social_secret)
        return {
            'email': new_user.email,
            'phone_number': new_user.phone_number,
            'username': new_user.username,
            'is_verified': new_user.is_verified,
            'providers': new_user.auth_providers,
            'tokens': new_user.tokens(),
        }

    # filtered_user_by_email = CustomUser.objects.filter(email=user_email)

    # if filtered_user_by_email.exists():
    #     if filtered_user_by_email[0].is_active == True:
    #         if provider == filtered_user_by_email[0].auth_provider:
    #             social_secret = "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"
    #             registered_user = authenticate(
    #                 email=user_email, password=social_secret
    #             )

    #             return {
    #                 "user_fullname": registered_user.user_fullname,
    #                 "user_email": registered_user.user_email,
    #                 "tokens": registered_user.tokens(),
    #             }

    #         elif (
    #             filtered_user_by_email[0].auth_provider == "email"
    #             or filtered_user_by_email[0].auth_provider == "google"
    #             or filtered_user_by_email[0].auth_provider == "facebook"
    #             or filtered_user_by_email[0].auth_provider == "linkedin"
    #             or filtered_user_by_email[0].auth_provider == "apple"
    #         ):

    #             return {
    #                 'email': filtered_user_by_email[0].email,
    #                 'phone_number': filtered_user_by_email[0].phone_number,
    #                 'username': filtered_user_by_email[0].username,
    #                 'is_verified': filtered_user_by_email[0].is_verified,
    #                 'tokens': filtered_user_by_email[0].tokens(),
                    
    #             }

    #         else:
    #             return {
    #                 "fail": f"'Please continue your login using ' {filtered_user_by_email[0].auth_provider}"
    #             }
    #     else:
    #         return {
    #             "fail": f"'inactive user ' {filtered_user_by_email[0].auth_provider}"
    #         }

    # else:
    #     social_secret = "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"

    #     current_time = datetime.datetime.now()
    #     current_time = current_time.strftime("%m%d%H%M%S%f")
    #     userid = current_time

    #     user = {
    #         "userid": userid,
    #         "user_fullname": generate_username(user_fullname),
    #         "user_email": user_email,
    #         "password": social_secret,
    #     }
    #     user = CustomUser.objects.create_user(**user)
    #     user.is_verified = True
    #     user.auth_provider = provider
    #     user.save()
    #     new_user = authenticate(email=user_email, password=social_secret)
    #     return {
    #         'email': new_user.email,
    #         'phone_number': new_user.phone_number,
    #         'username': new_user.username,
    #         'is_verified': new_user.is_verified,
    #         'tokens': new_user.tokens(),
    #     }