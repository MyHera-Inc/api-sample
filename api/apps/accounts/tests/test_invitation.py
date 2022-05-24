from http import client
from urllib import response
from django.contrib.auth import authenticate
from django.urls import resolve
from rest_framework import status
from rest_framework.reverse import reverse
from rest_framework.test import APITestCase
from api.apps.accounts.fixtures.factories import InvitationFactory

from api.apps.accounts.models import Invitation
from ..utils import (
    create_user,
    get_auth_token,
)


class InvitationTests(APITestCase):

    def setUp(self):
        self.user = create_user({
            "email": "testuser@gmail.com",
            "password": "testpassword123!",
            "first_name": "Test",
            "last_name": "User",
        })
        self.token = get_auth_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token}')
    
    def test_create_invitation(self):
        """ Create inivite test """
        url = reverse('accounts:invite-create')
        data = {
            'email': 'newuser@gmail.com',
            'first_name': 'New',
            'last_name': 'User',
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIsNotNone(response.data.get('data').get('id'))


    def test_invite_detail(self):
        """ Test the detail endpoint for an invite """
        invite_factory = InvitationFactory(email="tester@mail.com")
        url = reverse('accounts:invite-detail', kwargs={"id": invite_factory.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    

    def test_accept_invite(self):
        """ Test  accept invitation """
        self.client.logout()
        invite_factory = InvitationFactory(email="tester@mail.com", first_name="Tester", last_name="Lin")
        url = reverse("accounts:invite-accept", kwargs={"id": invite_factory.id})
        data = {
            "password": "Password123test"
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
