from rest_framework import renderers
import json

class CustomRenderer(renderers.JSONRenderer):

    charset='utf-8'
    # 'status_code': renderer_context['response'].status_code
    def render(self, data, accepted_media_type=None, renderer_context=None):
        if 'ErrorDetail' in str(data):
            response = json.dumps({'success': False, 'status_code': renderer_context['response'].status_code, 'message':data})
        else:
            response = {'success': True, 'status_code': renderer_context['response'].status_code}
            response.update(data)
            return json.dumps(response)
        return response