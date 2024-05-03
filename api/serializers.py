import re
from django.contrib.auth.models import Group
from django.contrib.auth.hashers import check_password
from django.core.exceptions import PermissionDenied
from rest_framework import serializers
from .models import User


class UserSerializer(serializers.ModelSerializer):
    old_password  = serializers.CharField(write_only=True, required=False)
    repeat_password  = serializers.CharField(write_only=True, required=False)
    groups = serializers.SlugRelatedField(many=True, queryset=Group.objects.all(),slug_field='name')

    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'email', 'password', 'old_password', 'repeat_password', 'groups', 'subscription', 'created', 'updated']
        extra_kwargs = {'password': {'write_only': True}}


    def to_internal_value(self, data):
        # Translation from pk to name Group representation
        user = self.context.get('request').user
        if 'groups' in data:
            valid_groups = []
            if user.is_staff or user.is_superuser:
                for group_name in data['groups']:
                    group, _ = Group.objects.get_or_create(name=group_name)
                    valid_groups.append(group.name)
            data['groups'] = valid_groups
        return super().to_internal_value(data)


    def validate_password(self, value):
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$', value):
            raise serializers.ValidationError(
                'Password must include: 8+ characters, one uppercase and one \
                lowercase letter, one digit, and one special character.'
            )
        return value


    def validate_groups(self, value):
        for group_name in value:
            group = Group.objects.get(name=group_name)
            group.user_set.add(self.instance)
        return value


    def get_fields(self):
        # Limits the subset of fields a non-admin user can see about another
        fields = super().get_fields()
        request = self.context.get('request')
        user = request.user
        admin_only_fields = ['email', 'password', 'old_password', 'repeat_password',
                             'groups', 'subscription', 'created', 'updated']
        if request and not (user == self.instance or user.is_staff or user.is_superuser):
            for field in admin_only_fields:
                fields.pop(field, None)
        return fields


    def validate(self, data):
            user = self.context.get('request').user
            if not user.is_staff and not user == self.instance:
                raise PermissionDenied('You are not authorized to edit this user')

            # Password update logic
            if 'password' in data and 'repeat_password' in data:
                password = data['password']
                repeat_password = data.pop('repeat_password')
                if self.instance:
                    if 'old_password' in data:
                        if not check_password(data['old_password'], self.instance.password):
                            raise serializers.ValidationError({'message':'Old password incorrect'})
                    elif not user.is_staff:
                        raise serializers.ValidationError(
                            {'message':'Provide your old password if you would like to update it'}
                        )

                data.pop('old_password', None)

                if password != repeat_password:
                    raise serializers.ValidationError({'message':'Passwords do not match'})

            # Email update logic
            if 'email' in data:
                if User.objects.filter(email=data['email']).count() > 0:
                    raise serializers.ValidationError(
                        {'message':'A user with that email already exists'}
                    )

            # Groups update logic
            if 'groups' in data:
                if not user.is_staff and not user.is_superuser:
                    raise PermissionDenied('You are not authorized to edit your groups')

            return data
