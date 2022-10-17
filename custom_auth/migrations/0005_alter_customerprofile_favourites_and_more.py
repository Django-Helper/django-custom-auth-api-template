# Generated by Django 4.1.2 on 2022-10-17 07:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('custom_auth', '0004_alter_customerprofile_user'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customerprofile',
            name='favourites',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='customerprofile',
            name='history',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='customerprofile',
            name='in_cart',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='customerprofile',
            name='save_address',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='customerprofile',
            name='save_cards',
            field=models.JSONField(default=list),
        ),
    ]