from django.contrib.auth.forms import UserCreationForm, UserChangeForm

from .models import CustomUser, StaffProfile


class CustomUserCreationForm(UserCreationForm):

    class Meta:
        model = CustomUser
        fields = ('email',)

    def save(self, commit=True):
        user = super(CustomUserCreationForm, self).save(commit=False)
        if user.is_staff or user.is_superuser:
            StaffProfile.objects.create(user=user)
        user.save()
        return user


class CustomUserChangeForm(UserChangeForm):

    class Meta:
        model = CustomUser
        fields = '__all__'