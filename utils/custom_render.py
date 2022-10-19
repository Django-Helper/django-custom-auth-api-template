from rest_framework import renderers
import json

class CustomJSONRenderer(renderers.JSONRenderer):

    charset='utf-8'
    def render(self, data, accepted_media_type=None, renderer_context=None):
        errors = []
        if 'ErrorDetail' in str(data):
            if isinstance(data, dict):
                if 'customer_profile' in data:
                    customer_profile = data.pop('customer_profile')
                    data.update(customer_profile)
                if 'admin_profile' in data:
                    admin_profile = data.pop('admin_profile')
                    data.update(admin_profile)
                if 'detail' in str(data):
                    errors.append("{} : {}".format('detail', " ".join(data['detail'])))
                else:
                    for field, value in data.items():
                        errors.append("{} : {}".format(field, " ".join(value)))
            else:
                for error in data:
                    errors.append(error)
            response = json.dumps({'success': False, 'messages':errors})
        else:
            response = {'success': True}
            response.update(data)
            return json.dumps(response)
        return response


# class CustomJSONRenderer(renderers.JSONRenderer):

#     def render(self, data, accepted_media_type=None, renderer_context=None):

#         response_data = {'message': '', 'errors': [], 'data': data, 'success': 'success'}

#         getattr(renderer_context.get('view').get_serializer().Meta,'resource_name', 'objects')

#         # call super to render the response
#         response = super(CustomJSONRenderer, self).render(response_data, accepted_media_type, renderer_context)

#         return response
