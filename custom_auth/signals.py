# code
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from .models import CustomUser, StaffProfile
 
 
@receiver(post_save, sender=CustomUser)
def create_profile(sender, instance, created, **kwargs):
    if created and instance.is_superuser:
        StaffProfile.objects.create(user=instance)
  
@receiver(post_save, sender=CustomUser)
def save_profile(sender, instance, **kwargs):
    if instance.is_superuser:
        instance.staff_profile.save()