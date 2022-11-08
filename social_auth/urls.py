from django.urls import path

from .views import (GoogleSocialAuthView, FacebookSocialAuthView, 
                    LinkedinSocialAuthView, AppleSocialAuthView,
                    TwitterSocialAuthView)

urlpatterns = [
    path("google/", GoogleSocialAuthView.as_view()),
    path("facebook/", FacebookSocialAuthView.as_view()),
    path("linkedin/", LinkedinSocialAuthView.as_view()),
    path("apple/", AppleSocialAuthView.as_view()),
    path("twitter/", TwitterSocialAuthView.as_view()),
]