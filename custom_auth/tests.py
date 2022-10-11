import email
from django.contrib.auth import get_user_model
from django.test import TestCase

# Create your tests here.

class CustomUsersManagersTests(TestCase):

    def test_create_user(self):
        User = get_user_model()
        user = User.objects.create_user(email='normal@user.com', password='foo', username='normal50', user_type=1)
        self.assertEqual(user.email, 'normal@user.com')
        self.assertEqual(user.username, 'normal50')
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

        with self.assertRaises(TypeError):
            User.objects.create_user()
        with self.assertRaises(TypeError):
            User.objects.create_user(email='')
        with self.assertRaises(TypeError):
            User.objects.create_user(username='')
        with self.assertRaises(TypeError):
            User.objects.create_user(user_type='')
        with self.assertRaises(ValueError):
            User.objects.create_user(email='', password="foo", username='normal50', user_type=1)
        with self.assertRaises(ValueError):
            User.objects.create_user(email='normal@user.com', password="foo", username='', user_type=1)
        with self.assertRaises(ValueError):
            User.objects.create_user(email='normal@user.com', password="foo", username='normal50', user_type='')

    def test_create_superuser(self):
        pass


