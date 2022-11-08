import email
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.conf import settings
import os

class Util:
    @staticmethod
    def send_email(data):
        email = EmailMessage(subject=data['email_subject'], body=data['email_body'], to=[data['to_email']])
        email.send()

    @staticmethod
    def send_email_with_template(html_content, data, namee= None):
        email = EmailMultiAlternatives(
            # subject
            data["email_subject"],
            # content
            data["email_body"],
            # from email
            settings.EMAIL_HOST_USER,
            # to email
            [data["to_email"]],
        )

        email.attach_alternative(html_content, "text/html")
        if namee != None:
            dir = settings.BASE_DIR
            file = str(dir)+'/'+ namee

            email.attach_file(file)

        email.send()

        if namee != None:
            os.remove(str(file))