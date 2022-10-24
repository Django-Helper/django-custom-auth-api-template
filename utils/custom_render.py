from rest_framework import renderers
from django.core.serializers.json import DjangoJSONEncoder
import json

class CustomJSONRenderer(renderers.JSONRenderer):

    charset='utf-8'
    def render(self, data, accepted_media_type=None, renderer_context=None):
        errors = []
        print('custom renderer:', data)
        # if 'ErrorDetail' in str(data):
        if 'errors' in str(data):
            if isinstance(data['errors'], dict):
                if 'customer_profile' in data['errors']:
                    customer_profile = data['errors'].pop('customer_profile')
                    data['errors'].update(customer_profile)
                if 'admin_profile' in data['errors']:
                    admin_profile = data['errors'].pop('admin_profile')
                    data['errors'].update(admin_profile)
                if 'detail' in str(data['errors']):
                    errors.append("{} : {}".format('detail', " ".join(data['errors']['detail'])))
                else:
                    for field, value in data['errors'].items():
                        errors.append("{} : {}".format(field, " ".join(value)))
            else:
                for error in data['errors']:
                    errors.append(error)
            response = json.dumps({'success': False, 'message': data['message'] ,'errors':errors})
        else:
            response = {'success': True}
            response['message'] = data['message'] if 'message' in data else 'Successfull'
            response['data'] = data['data'] if 'data' in data else data
            # if 'data' not in data:
            #     response.update({'data': []})
            # else:
            # response.update(data)
            return json.dumps(response, cls=DjangoJSONEncoder)
        return response


# class CustomJSONRenderer(renderers.JSONRenderer):

#     def render(self, data, accepted_media_type=None, renderer_context=None):

#         response_data = {'message': '', 'errors': [], 'data': data, 'success': 'success'}

#         getattr(renderer_context.get('view').get_serializer().Meta,'resource_name', 'objects')

#         # call super to render the response
#         response = super(CustomJSONRenderer, self).render(response_data, accepted_media_type, renderer_context)

#         return response
