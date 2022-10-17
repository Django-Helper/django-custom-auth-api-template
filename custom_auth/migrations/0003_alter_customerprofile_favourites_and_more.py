# Generated by Django 4.1.2 on 2022-10-17 07:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('custom_auth', '0002_alter_customerprofile_user_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customerprofile',
            name='favourites',
            field=models.JSONField(blank=True),
        ),
        migrations.AlterField(
            model_name='customerprofile',
            name='history',
            field=models.JSONField(blank=True),
        ),
        migrations.AlterField(
            model_name='customerprofile',
            name='in_cart',
            field=models.JSONField(blank=True),
        ),
        migrations.AlterField(
            model_name='customerprofile',
            name='profile_picture',
            field=models.ImageField(blank=True, upload_to='upload/customer_profile_picture/'),
        ),
        migrations.AlterField(
            model_name='customerprofile',
            name='save_address',
            field=models.JSONField(blank=True),
        ),
        migrations.AlterField(
            model_name='customerprofile',
            name='save_cards',
            field=models.JSONField(blank=True),
        ),
    ]
