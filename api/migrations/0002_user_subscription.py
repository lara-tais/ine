# Generated by Django 5.0 on 2024-05-02 12:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='subscription',
            field=models.CharField(default='inactive', max_length=8),
        ),
    ]
