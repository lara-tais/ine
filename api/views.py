from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from .serializers import UserSerializer
from .permissions import (CreateUserPermission, EditUserPermission, EditUserPermission,
                          DeleteUserPermission, ReadUserPermission, ReadUserPermission)
from .models import User

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes_by_action = {
        'create': [CreateUserPermission],
        'update': [EditUserPermission],
        'partial_update': [EditUserPermission],
        'destroy': [DeleteUserPermission],
        'list': [ReadUserPermission],
        'retrieve': [ReadUserPermission],
    }

    def get_permissions(self):
        if self.action in self.permission_classes_by_action:
            return [permission() for permission in self.permission_classes_by_action[self.action]]
        else:
            return [permission() for permission in self.permission_classes]
