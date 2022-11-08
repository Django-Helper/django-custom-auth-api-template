from google.auth.transport import requests as google_auth_request
from google.oauth2 import id_token


class Google:
    # validate method Queries the Google oAUTH2 api to fetch the user info
    @staticmethod
    def validate(auth_token):

        try:
            print('google auth token validation')
            idinfo = id_token.verify_oauth2_token(
                auth_token, google_auth_request.Request()
            )
            print('info',idinfo)
            if "accounts.google.com" in idinfo["iss"]:
                return idinfo

        except Exception as e:
            return "The token is either invalid or has expired."


import facebook

import json


class Facebook:

    #       validate method Queries the facebook GraphAPI to fetch the user info
    @staticmethod
    def validate(auth_token):

        try:
            print('facebook auth token')
            graph = facebook.GraphAPI(access_token=auth_token)
            profile = graph.request("/me?fields=name,email,picture")
            print('facebook profile:', profile)
            return profile
        except Exception as e:
            print('facebook exception:',e)
            return "The token is invalid or expired."


# import linkedin
import requests
from requests.structures import CaseInsensitiveDict


class Linkedin:
    @staticmethod
    def validate(auth_token):

        try:

            url = f"https://api.linkedin.com/v2/me?oauth2_access_token={auth_token}"
            headers = CaseInsensitiveDict()
            headers["Accept"] = "*/*"
            resp_name = requests.get(url, headers=headers)
            resp_dict_name = resp_name.json()
            print(resp_dict_name)
            resp_fullname = (
                resp_dict_name["localizedFirstName"]
                + " "
                + resp_dict_name["localizedLastName"]
            )


            url = "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))"
            headers = CaseInsensitiveDict()
            headers["Accept"] = "application/json"
            headers["Authorization"] = f"Bearer {auth_token}"
            resp_mail = requests.get(url, headers=headers)
            resp_dict_mail = resp_mail.json()
            print(resp_dict_mail)
            resp_mail = resp_dict_mail["elements"][0]["handle~"]["emailAddress"]
            

            resp_data = {"name": resp_fullname, "email": resp_mail, "picture": None}
            print(resp_data)
            return resp_data

        except:
            return "The token is invalid or expired."


import jwt


class Apple:
    @staticmethod
    def validate(auth_token):

        try:
            # print("auth_token============", "auth_token" )

            verified_payload = jwt.decode(auth_token, options={"verify_signature": False})

            # print(verified_payload['email'])
            
            resp_data = {"name": verified_payload['email'], "email": verified_payload['email'], "picture": None}
            return resp_data

        except Exception as e:
            # print('Error: ', str(e))
            return "The token is invalid or expired."

import twitter
import os
from rest_framework import serializers

class Twitter:

    @staticmethod
    def validate(access_token_key, access_token_secret):
        """
        validate_twitter_auth_tokens methods returns a twitter
        user profile info
        """

        consumer_api_key = "nYYoQcMmcKGhwvd5j5rhNxnWJ"
        consumer_api_secret_key = "AH15YeDM3bUK1eLIhJVr8kSkEQyearxdbl6zVAUqoPYrFabfeK"

        try:
            api = twitter.Api(
                consumer_key=consumer_api_key,
                consumer_secret=consumer_api_secret_key,
                access_token_key=access_token_key,
                access_token_secret=access_token_secret
            )

            user_profile_info = api.VerifyCredentials(include_email=True)
            return user_profile_info.__dict__

        except Exception as identifier:

            raise serializers.ValidationError({
                "tokens": ["The tokens are invalid or expired"]})