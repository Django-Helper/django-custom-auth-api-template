# Generated by Django 4.1.2 on 2022-10-19 12:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('custom_auth', '0006_adminrole_alter_customuser_user_type_adminprofile'),
    ]

    operations = [
        migrations.AlterField(
            model_name='adminprofile',
            name='profile_picture',
            field=models.ImageField(blank=True, null=True, upload_to='upload/admin_profile_picture/'),
        ),
    ]