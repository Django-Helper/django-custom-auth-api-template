from django.contrib.auth.tokens import PasswordResetTokenGenerator
# from django.utils import six

class PrimaryEmailUpdateTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        email_field = user.get_email_field_name()
        email = getattr(user, email_field, "") or ""
        # return (
        #     six.text_type(user.pk) + six.text_type(timestamp) +
        #     six.text_type(email)
        # )
        # return f"{user.pk}{user.password}{login_timestamp}{timestamp}{email}"
        return f"{user.pk}{timestamp}{email}"

primary_email_update_token = PrimaryEmailUpdateTokenGenerator()

class PrimaryPhoneUpdateTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        phone_number = getattr(user, "phone_number", "") or ""
        # return (
        #     six.text_type(user.pk) + six.text_type(timestamp) +
        #     six.text_type(phone_number)
        # )
        return f"{user.pk}{timestamp}{phone_number}"

primary_phone_update_token = PrimaryPhoneUpdateTokenGenerator()