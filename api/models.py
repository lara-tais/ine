import requests
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token

def get_subscription():
    response = requests.get('https://subscriptions.fake.service.test/api/v1/users/:uuid')
    return response.data['subscription']

class User(AbstractUser):
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    subscription = models.CharField(max_length=8, default='inactive')

    def save(self, *args, **kwargs):
        if not self.pk:
            self.subscription = get_subscription()
        super(User, self).save(*args, **kwargs)

@receiver(post_save, sender=User)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)
