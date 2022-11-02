from rest_framework import serializers

from .helper import Google, Facebook, Linkedin, Apple
from .register import register_social_user
import os
from rest_framework.exceptions import AuthenticationFailed
import datetime


class GoogleSocialAuthSerializer(serializers.Serializer):
    auth_token = serializers.CharField()

    def validate_auth_token(self, auth_token):
        user_data = Google.validate(auth_token)
        print('google:', user_data)
        try:
            user_data["sub"]
        except Exception as e:
            print('exception:', e)
            raise serializers.ValidationError(
                "The token is invalid or expired. Please login again."
            )
        # googleClientID_web = (
        #     "187084527164-a5mg5g9dh6k6022uo1elhciaea49lm2e.apps.googleusercontent.com"
        # )
        # googleClientID_android = (
        #     "187084527164-2ten6tf1pf9sshiah762aghuhofj2lc8.apps.googleusercontent.com"
        # )
        # googleClientID_iso = (
        #     "187084527164-tma96b5qiakd594kf2u5mjt61vvnfoe4.apps.googleusercontent.com"
        # )

        google_client = [
            "489042626314-gjv8aespnd3iskhog5s2ic1dorvprr82.apps.googleusercontent.com"
        ]

        if (user_data["aud"] not in google_client):
            raise AuthenticationFailed("oops, who are you?")
        userid = user_data["sub"]
        user_email = user_data["email"]
        user_fullname = user_data["name"]
        user_image = user_data["picture"]

        provider = "google"

        return register_social_user(
            provider=provider,
            user_email=user_email,
            user_fullname=user_fullname,
            user_image=user_image,
        )


class FacebookSocialAuthSerializer(serializers.Serializer):
    """Handles serialization of facebook related data"""

    auth_token = serializers.CharField()

    def validate_auth_token(self, auth_token):

        user_data = Facebook.validate(auth_token)
        print('facebook:', user_data)
        try:
            user_email = user_data["email"]
            user_fullname = user_data["name"]
            user_image = user_data["picture"]["data"]["url"]
            provider = "facebook"
            return register_social_user(
                provider=provider,
                user_email=user_email,
                user_fullname=user_fullname,
                user_image=user_image,
            )
        except Exception as identifier:

            raise serializers.ValidationError(
                "The token  is invalid or expired. Please login again."
            )


class LinkedinSocialAuthSerializer(serializers.Serializer):
    """Handles serialization of linkedin related data"""

    auth_token = serializers.CharField()

    def validate_auth_token(self, auth_token):
        user_data = Linkedin.validate(auth_token)

        try:
            user_email = user_data["email"]
            user_fullname = user_data["name"]
            user_image = user_data["picture"]
            provider = "linkedin"
            return register_social_user(
                provider=provider,
                user_email=user_email,
                user_fullname=user_fullname,
                user_image=user_image,
            )
        except Exception as identifier:

            raise serializers.ValidationError(
                "The token  is invalid or expired. Please login again."
            )


class AppleSocialAuthSerializer(serializers.Serializer):
    """Handles serialization of linkedin related data"""

    auth_token = serializers.CharField()

    def validate_auth_token(self, auth_token):
        user_data = Apple.validate(auth_token)
        try:
            user_email = user_data["email"]
            user_fullname = user_data["name"]
            user_image = user_data["picture"]
            provider = "Apple"
            return register_social_user(
                provider=provider,
                user_email=user_email,
                user_fullname=user_fullname,
                user_image=user_image,
            )
        except Exception as identifier:

            raise serializers.ValidationError(
                "The token  is invalid or expired. Please login again."
            )