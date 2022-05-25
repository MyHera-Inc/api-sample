from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DefaultUserAdmin
from .models import User, VerificationToken, UserInvitation


class UserAdmin(DefaultUserAdmin):
    fieldsets = DefaultUserAdmin.fieldsets + (
        (None, {'fields': ('is_verified',)}),
    )
    add_fieldsets = DefaultUserAdmin.add_fieldsets + (
        (None, {'fields': ('is_verified',)}),
    )


admin.site.register(User, UserAdmin)
admin.site.register(VerificationToken)
admin.site.register(UserInvitation)
