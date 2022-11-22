from rest_framework.permissions import BasePermission
from rest_framework.exceptions import MethodNotAllowed
from django.contrib.auth.models import Permission, Group
from django.db.models import Q

class CustomPermission(BasePermission):
    message = "You do not have permission to perform action"
    permission_map = {
        "GET": "{app_label}.view_{model_name}",
        "POST": "{app_label}.add_{model_name}",
        "PUT": "{app_label}.change_{model_name}",
        "PATCH": "{app_label}.change_{model_name}",
        "DELETE": "{app_label}.delete_{model_name}",
    }

    def _get_permission(self, method, perm_slug):
        app, model = perm_slug.split(".")
        if method not in self.permission_map:
            raise MethodNotAllowed(method)
        perm = self.permission_map.get(method).format(app_label=app, model_name=model)
        return perm

    def has_permission(self, request, view):
        perm = self._get_permission(
            method=request.method, perm_slug=view.perm_slug
        )
        if request.user.has_perm(perm):
            return True
        return False

def has_field_permission(request, app, model, field):
    permission_map = {
        # "GET": "{app_label}.view_{model_name}__{field_name}",
        "PUT": "{app_label}.change_{model_name}__{field_name}",
        "PATCH": "{app_label}.change_{model_name}__{field_name}",
    }

    if request.method not in permission_map:
        raise MethodNotAllowed(request.method)
    perm = permission_map.get(request.method).format(app_label=app, model_name=model, field_name=field)

    if request.user.has_perm(perm):
        return True
    return False

def access_permissions_fields(request,perm_slug):
    if request.method == 'GET':
        app, model = perm_slug.split(".")
        user = request.user
        permissions = Permission.objects.filter(Q(group__user=user) & Q(codename__icontains='view') & Q(codename__icontains='__') & Q(content_type__app_label=app) & Q(content_type__model=model)).values('codename')
        return [permission['codename'].split('__')[-1] for permission in permissions]
    raise MethodNotAllowed(request.method)

