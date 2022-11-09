from celery import shared_task
import email
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.conf import settings
import os

@shared_task(bind = True)
def send_email(self, **kwargs):
    data = kwargs['data']
    email = EmailMessage(subject=data['email_subject'], body=data['email_body'], to=[data['to_email']])
    email.send()
    return "Email Send Successfully!"