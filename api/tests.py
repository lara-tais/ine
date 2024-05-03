from copy import deepcopy
from unittest import mock
from django.test import TestCase
from django.contrib.auth.models import Group
from rest_framework.test import APIClient
from rest_framework import status
from .serializers import UserSerializer
from .models import User


user_data = {
    'username': 'johndoe',
    'first_name': 'John',
    'last_name': 'Doe',
    'email': 'johndoe@ine.test',
    'old_password': 'Password123!',
    'password': 'SuperSecurePasswd2!',
    'repeat_password': 'SuperSecurePasswd2!',
    'groups': [
        'sales',
        'support',
    ]
}

@mock.patch('api.models.get_subscription', mock.MagicMock(return_value='active'))
class UserViewSetTests(TestCase):

    def setUp(self):
        self.client = APIClient()

        # Users creation
        with mock.patch('api.models.get_subscription') as mock_get_subscription:
            mock_get_subscription.return_value = "active"

            # Create regular User
            self.user = User.objects.create_user(
                            username='test_user',
                            password='Password123!'
                            )
            user_token = self.client.post(
                            '/api-token-auth/',
                            {'username':'test_user', 'password':'Password123!'},
                            format='json'
                            )
            self.user_token = user_token.data['token']

            # Create admin user
            self.admin = User.objects.create_user(
                            username='test_admin',
                            password='Password123!',
                            is_staff=True
                            )
            admin_token = self.client.post(
                            '/api-token-auth/',
                            {'username':'test_admin', 'password':'Password123!'},
                            format='json')
            self.admin_token = admin_token.data['token']

            # Create superuser
            self.superuser = User.objects.create_superuser(
                                username='test_superuser',
                                password='Password123!'
                                )
            superuser_token = self.client.post(
                                '/api-token-auth/',
                                {'username':'test_superuser', 'password':'Password123!'},
                                format='json'
                                )
            self.superuser_token = superuser_token.data['token']

            # Create third party user
            self.third_party = User.objects.create_user(
                                username='test_third',
                                password='Password123!',
                                email='preexisting@email.org')
            third_party_token = self.client.post('/api-token-auth/',
                                {'username':'test_third', 'password':'Password123!'},
                                format='json'
                                )
            self.third_party_token = third_party_token.data['token']

            # Log in admin user as default
            self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token}')


    ## AUTH TESTS

    def test_good_auth(self):
        """Log in success with correct Token"""
        response = self.client.get('/users/', format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_bad_auth(self):
        """Log in failure with bad Token"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token error')
        response = self.client.get('/users/', format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


    ## USER CREATE TESTS

    def test_create_user_success(self):
        """User creation is successful"""
        response = self.client.post('/users/', user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.filter(username='johndoe').count(), 1)

    def test_create_user_serializer(self):
        """User creation returns correct serializer fields"""
        response = self.client.post('/users/', user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        json = response.data
        self.assertIn('created', json)
        self.assertIn('updated', json)
        self.assertIn('subscription', json)

    def test_create_user_forbidden(self):
        """Regular Users can't create other Users"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.third_party_token}')
        response = self.client.post('/users/', user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_create_user_passwords_dont_match(self):
        """User creation fails if passwords don't match"""
        mismatched_password_data = deepcopy(user_data)
        mismatched_password_data["password"] = 'different password'
        response = self.client.post('/users/', mismatched_password_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_user_password_too_simple(self):
        """User creation fails if password too simple"""
        simple_password_data = deepcopy(user_data)
        simple_password_data["password"] = 'simple_password'
        simple_password_data["repeat_password"] = 'simple_password'
        response = self.client.post('/users/', simple_password_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_user_group_does_not_exist(self):
        """User creation generates groups if they don't exist"""
        self.assertEqual(Group.objects.filter(name='sales').count(), 0)
        response = self.client.post('/users/', user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Group.objects.filter(name='sales').count(), 1)


    # TEST RETRIEVE

    def test_retrieve_user_by_self(self):
        """User retrieval successful"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.user_token}')
        response = self.client.get('/users/{}/'.format(self.user.pk))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('username', response.data)

    def test_retrieve_user_by_staff(self):
        """User retrieval by an admin uses the extended serializer"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token}')
        response = self.client.get('/users/{}/'.format(self.user.pk))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('email', response.data)

    def test_retrieve_user_by_non_staff(self):
        """User retrieval by a non-admin uses the limited serializer"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.third_party_token}')
        response = self.client.get('/users/{}/'.format(self.user.pk))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotIn('email', response.data)


    ### TEST UPDATE

    def test_update_user_full_update_success(self):
        """Full User update successful"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token}')
        put_user_data = deepcopy(user_data)
        put_user_data['last_name'] = 'New Last Name'
        response = self.client.put('/users/{}/'.format(self.user.pk), put_user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        obj = User.objects.get(pk=self.user.pk)
        self.assertEqual(obj.last_name, 'New Last Name')

    def test_update_user_full_update_error(self):
        """User retrieval through PUT fails if data incomplete"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token}')
        put_user_data = {'last_name': 'New Last Name'}
        response = self.client.put('/users/{}/'.format(self.user.pk), put_user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_user_by_self(self):
        """Partial User update by self is successful"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.user_token}')
        data = {'last_name': 'New Last Name'}
        response = self.client.patch('/users/{}/'.format(self.user.pk), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        obj = User.objects.get(pk=self.user.pk)
        self.assertEqual(obj.last_name, 'New Last Name')
    #
    def test_update_user_by_staff(self):
        """Partial User update by admin is successful"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token}')
        data = {'last_name': 'New Last Name'}
        response = self.client.patch('/users/{}/'.format(self.user.pk), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        obj = User.objects.get(pk=self.user.pk)
        self.assertEqual(obj.last_name, 'New Last Name')

    def test_update_user_by_non_staff(self):
        """Partial User update by non-admin third party is unsuccessful"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.third_party_token}')
        data = {'last_name': 'New Last Name'}
        response = self.client.patch('/users/{}/'.format(self.user.pk), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        obj = User.objects.get(pk=self.user.pk)
        self.assertNotEqual(obj.last_name, 'New Last Name')

    def test_update_password_by_self_success(self):
        """Password update by self is successful"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.user_token}')
        data = {
            'old_password': 'Password123!',
            'password': 'NewPassword321!',
            'repeat_password': 'NewPassword321!'
        }
        response = self.client.patch('/users/{}/'.format(self.user.pk), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_update_password_by_self_error(self):
        """Password update by self without previous password is unsuccessful"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.user_token}')
        data = {'password': 'NewPassword321!', 'repeat_password': 'NewPassword321!'}
        response = self.client.patch('/users/{}/'.format(self.user.pk), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_password_by_staff_success(self):
        """Password update by admin is successful"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token}')
        data = {'password': 'NewPassword321!', 'repeat_password': 'NewPassword321!'}
        response = self.client.patch('/users/{}/'.format(self.user.pk), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_update_group_by_staff(self):
        """Groups update by admin is successful"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token}')
        data = {"groups": ["sales"]}
        response = self.client.patch('/users/{}/'.format(self.user.pk), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['groups'], ['sales'])

    def test_update_group_by_self(self):
        """Groups update by regular User is unsuccessful"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.user_token}')
        data = {'groups': ['sales', 'support']}
        response = self.client.patch('/users/{}/'.format(self.user.pk), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_update_email_success(self):
        """Email update is successful if email unique"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.user_token}')
        data = {'email': 'new@email.org'}
        response = self.client.patch('/users/{}/'.format(self.user.pk), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_update_email_error(self):
        """Email update is unsuccessful if email not unique"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.user_token}')
        data = {'email': 'preexisting@email.org'}
        response = self.client.patch('/users/{}/'.format(self.user.pk), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    ### DELETE TESTS

    def test_user_cannot_delete_user(self):
        """Regular Users cannot delete each other"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.third_party_token}')
        pk = self.user.pk
        response = self.client.delete('/users/{}/'.format(pk))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        user = User.objects.filter(pk=pk)
        self.assertEqual(user.count(),1)

    def test_staff_can_delete_user(self):
        """admin can delete regular Users"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token}')
        pk = self.user.pk
        response = self.client.delete('/users/{}/'.format(pk))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        user = User.objects.filter(pk=pk)
        self.assertEqual(user.count(), 0)

    def test_staff_cannot_delete_staff(self):
        """admin cannot delete superuser"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token}')
        pk = self.superuser.pk
        response = self.client.delete('/users/{}/'.format(pk))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        user = User.objects.filter(pk=pk)
        self.assertEqual(user.count(), 1)

    def test_superuser_can_delete_staff(self):
        """superuser can delete admin"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.superuser_token}')
        pk = self.admin.pk
        response = self.client.delete('/users/{}/'.format(pk))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        user = User.objects.filter(pk=pk)
        self.assertEqual(user.count(), 0)
