from __future__ import absolute_import, unicode_literals
import os

from celery import Celery
from django.conf import settings
from celery.schedules import crontab

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auth_api.settings')

app = Celery('auth_api')
app.conf.enbale_utc = False

app.conf.update(timezone = 'Asia/Dhaka')

app.config_from_object(settings, namespace='CELERY')

# Celery Beat Settings
# app.conf.beat_schedule = {
#     'send-mail-every-day-at-5-pm': {
#         'task': 'send_mail.tasks.send_mail_func',
#         'schedule': crontab(hour = 17, minute = 30),
#         # 'args': ()
#     }
# }

app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))