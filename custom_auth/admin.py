from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, CustomerProfile, StaffProfile



# admin.site.register(CustomUser, UserAdmin)

# Register your models here.

# admin.site.register(CustomUser)

@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ['id', 'email', 'phone_number', 'username', 'is_active', 'is_verified', 'is_staff',
    'is_superuser', 'last_login', 'created_at', 'updated_at']

# admin.site.register(CustomUser, CustomUserAdmin)

admin.site.register(CustomerProfile)
admin.site.register(StaffProfile)
