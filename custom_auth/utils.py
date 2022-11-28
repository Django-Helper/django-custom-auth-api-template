import datetime
import jwt
import requests
from auth_api import settings
from django.urls import reverse
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.models import Permission, Group
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from django.core.mail import EmailMessage, EmailMultiAlternatives
from rest_framework import serializers

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


def get_staff_registration_verify_email_data(**kwargs):
    user_id = kwargs['user_id']
    username = kwargs['username']
    email = kwargs['email']
    request = kwargs['request']
    password = kwargs['password']
    payload = {
                "user_id": str(user_id),
                "exp": datetime.datetime.utcnow()
                + datetime.timedelta(minutes=5, seconds=00),
                "iat": datetime.datetime.utcnow(),
            }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    # token = RefreshToken.for_user(user).access_token
    current_site = get_current_site(request).domain
    relativeLink = reverse('register_email_verify')
    absurl = 'http://'+current_site+relativeLink+'?token='+str(token)
    email_body = 'Hi '+username+' Use link below to verify your email \n'+absurl+'\n'+"Your Temporary Password is:"+'\n'+password
    data = {"email_body":email_body, "to_email": email, "email_subject": 'Verify your email'}
    return data


def send_email_async(data):
    url = 'http://192.168.50.200:80/api/v1/send_email/'
    # X_API_KEY = 'qCqkmKdf.7vAb1A7cJRLTIQ1xpUGUBrooJ7cRaJ35'
    X_API_KEY = 'S6IXUApL.dlLlGlCbrL64vyC5qFVdIOwn1JjYQYdv'

    HEADER = {
        'Content-Type': 'application/json',
        'x-api-key': X_API_KEY
    }
    # header = {'Content-Type': 'application/json','x-api-key': os.environ.get('BARBQTONIGHT_BACKEND_X_API_KEY')}
    response = requests.post(url, json=data, headers=HEADER)
    return response

def structure_role_permissions(permissions):
    results = []
    for permission in permissions:
            find_module = next((item for item in results if item['name'] == permission['content_type__app_label']), None)
            if find_module:
                find_model = next((item for item in find_module['models'] if item['name'] == permission['content_type__model']), None)
                if find_model:
                    split_codename = permission['codename'].split('__')
                    if len(split_codename) > 1:
                        find_attribute = next((item for item in find_model['attributes'] if item['name'] == split_codename[-1]), None)
                        if find_attribute:
                            if permission['codename'] not in find_attribute['permissions']:
                                find_attribute['permissions'].append(permission['codename'])
                        else:
                            find_model['attributes'].append({'name':split_codename[-1],'permissions':[permission['codename']]})
                    else:
                        if permission['codename'] not in find_model['permissions']:
                            find_model['permissions'].append(permission['codename'])
                else:
                    split_codename = permission['codename'].split('__')
                    if len(split_codename) > 1:
                        model = {'name': None, 'permissions': [], 'attributes': []}
                        model['name'] = permission['content_type__model']
                        model['attributes'].append({'name': split_codename[-1], 'permissions':[permission['codename']]})
                        find_module['models'].append(model)
                    else:
                        find_module['models'].append({'name': permission['content_type__model'], 'permissions':[permission['codename']], 'attributes': []})
            else:
                split_codename = permission['codename'].split('__')
                if len(split_codename) > 1:
                    module = {'name': None, 'models': []}
                    module['name'] = permission['content_type__app_label']
                    model = {'name': None, 'permissions': [], 'attributes': []}
                    model['name'] = permission['content_type__model']
                    model['attributes'].append({'name': split_codename[-1], 'permissions': [permission['codename']]})
                    module['models'].append(model)
                    results.append(module)
                else:
                    results.append({'name': permission['content_type__app_label'], 'models': [{'name': permission['content_type__model'], 'permissions': [permission['codename']], 'attributes':[]}]})
    return results

def get_permissions(permission_objs):
    codenames = [item['codename'] for item in permission_objs]
    content_type__app_labels = [item['content_type__app_label'] for item in permission_objs]
    permissions = Permission.objects.filter(Q(codename__in=codenames) & Q(content_type__app_label__in=content_type__app_labels))
    return permissions



def do_exit_contenttype(values):
    for value in values:
        total_contenttype=ContentType.objects.filter(app_label=value).count()
        if total_contenttype == 0:
            raise serializers.ValidationError(f'{value} content_type__app_label does not exist!')

def do_exist_permissions(values):
    for value in values:
        try:
            Permission.objects.get(codename=value)
        except:
            raise serializers.ValidationError(f'{value} permission does not exist!')
        else:
            continue

def do_exist_permissions(model, values, attribute_name):
        kwargs = {
        '{0}__{1}'.format(attribute_name, 'in'): values,
        }
        return model.objects.filter(**kwargs).count() == len(values)