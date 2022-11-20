from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, CustomerProfile, StaffProfile
from .forms import CustomUserCreationForm, CustomUserChangeForm



# admin.site.register(CustomUser, UserAdmin)

# Register your models here.

# admin.site.register(CustomUser)

# @admin.register(CustomUser)
# class CustomUserAdmin(admin.ModelAdmin):
#     list_display = ['id', 'email', 'phone_number', 'username', 'is_active', 'is_verified', 'is_staff',
#     'is_superuser', 'last_login', 'created_at', 'updated_at']

# admin.site.register(CustomUser, CustomUserAdmin)


# class ReadOnlyAdminMixin:

#     def has_add_permission(self, request):
#         return False

#     def has_change_permission(self, request, obj=None):

#         if request.user.has_perm('inventory.change_product'):
#             return True
#         else:
#             return False

#     def has_delete_permission(self, request, obj=None):
#         return False

#     def has_view_permission(self, request, obj=None):
#         return True

class CustomUserAdmin(UserAdmin):
    add_form = CustomUserCreationForm
    form = CustomUserChangeForm
    model = CustomUser
    list_display = ['id', 'email', 'phone_number', 'username', 'is_active', 'is_verified', 'is_staff',
    'is_superuser', 'last_login', 'created_at', 'updated_at']

    # list_filter = ('email', 'is_staff', 'is_active',)
    fieldsets = (
        (None, {'fields': ('email', 'password', 'username', 'phone_number')}),
        ('Permissions', {'fields': ('is_staff', 'is_active', 'is_verified', 'is_superuser', 'groups', 'user_permissions')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'phone_number', 'password1', 'password2', 'is_staff', 'is_active')}
        ),
    )
    search_fields = ('email',)
    ordering = ('email',)


admin.site.register(CustomUser, CustomUserAdmin)

admin.site.register(CustomerProfile)
admin.site.register(StaffProfile)
