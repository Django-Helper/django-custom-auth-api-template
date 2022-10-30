from google.auth.transport import requests as google_auth_request
from google.oauth2 import id_token


class Google:
    # validate method Queries the Google oAUTH2 api to fetch the user info
    @staticmethod
    def validate(auth_token):

        try:
            idinfo = id_token.verify_oauth2_token(
                auth_token, google_auth_request.Request()
            )

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
            graph = facebook.GraphAPI(access_token=auth_token)
            profile = graph.request("/me?fields=name,email,picture")

            return profile
        except:
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
            resp_mail = resp_dict_mail["elements"][0]["handle~"]["emailAddress"]
            

            resp_data = {"name": resp_fullname, "email": resp_mail, "picture": None}
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