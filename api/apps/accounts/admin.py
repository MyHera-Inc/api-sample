from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DefaultUserAdmin
from .models import User, VerificationToken, Invitation


class UserAdmin(DefaultUserAdmin):
    fieldsets = DefaultUserAdmin.fieldsets + (
        (None, {'fields': ('is_verified',)}),
    )
    add_fieldsets = DefaultUserAdmin.add_fieldsets + (
        (None, {'fields': ('is_verified',)}),
    )


class InvitationAdmin(admin.ModelAdmin):
    list_display = ["id","first_name","last_name","email","is_active","invite_by"]
    search_fields = ["first_name","last_name","email"]


admin.site.register(User, UserAdmin)
admin.site.register(VerificationToken)
admin.site.register(Invitation)