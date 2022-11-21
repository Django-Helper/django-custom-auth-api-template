import datetime
import jwt
from auth_api import settings
from django.urls import reverse
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.models import Permission, Group
from django.db.models import Q

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


def get_staff_registration_verify_email_data(user, password, request):
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
    email_body = 'Hi '+user.username+' Use link below to verify your email \n'+absurl+'\n'+"Your Temporary Password is:"+'\n'+password
    data = {'email_body':email_body, 'to_email': user.email, 'email_subject': 'Verify your email'}
    return data

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
                            find_attribute['permissions'].append(permission['codename'])
                        else:
                            find_model['attributes'].append({'name':split_codename[-1],'permissions':[permission['codename']]})
                    else:
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
                    module['models'].append[model]
                    results.append(module)
                else:
                    results.append({'name': permission['content_type__app_label'], 'models': [{'name': permission['content_type__model'], 'permissions': [permission['codename']], 'attributes':[]}]})
    return results

def get_permissions(permission_objs):
    codenames = [item['codename'] for item in permission_objs]
    content_type__app_labels = [item['content_type__app_label'] for item in permission_objs]
    permissions = Permission.objects.filter(Q(codename__in=codenames) & Q(content_type__app_label__in=content_type__app_labels))
    return permissions