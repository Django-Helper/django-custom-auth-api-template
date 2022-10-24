from urllib import request
from rest_framework.views import exception_handler

# def custom_exception_handler(exc, context):
#     response = exception_handler(exc, context)
#     if response is not None:
#         response.data['status_code'] = response.status_code
#     return response


def custom_exception_handler(exc, context):
  # Call REST framework's default exception handler first,
  # to get the standard error response.
  response = exception_handler(exc, context)

  # Now add the HTTP status code to the response.
  if response is not None:

    errors = []

    message = response.data.get('detail')
    print('custom exception:', response.data)
    if not message:
        for field, value in response.data.items():
            errors.append("{} : {}".format(field, " ".join(value)))
        response.data = {'message': 'Bad Request', 'errors': errors, 'success': False}
    else:
        response.data = {'message': message, 'errors': [message],'success': False}

  return response