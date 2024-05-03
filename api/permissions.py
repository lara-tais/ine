from rest_framework.permissions import BasePermission

class CreateUserPermission(BasePermission):
    # Only admin roles can create a User
    def has_permission(self, request, view):
        return request.user.is_superuser or request.user.is_staff

class EditUserPermission(BasePermission):
    # Admin roles and itself can edit a User
    def has_object_permission(self, request, view, obj):
        return request.user.is_superuser or request.user.is_staff or obj == request.user

class DeleteUserPermission(BasePermission):
    def has_object_permission(self, request, view, obj):
        # Superusers can delete any User
        if request.user.is_superuser:
            return True
        # Regular Users can't delete other Users
        if not request.user.is_staff:
            return False
        return not obj.is_superuser

class ReadUserPermission(BasePermission):
    # Any User can see other Users
    def has_permission(self, request, view):
        return request.user.is_authenticated
