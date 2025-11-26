# offers/signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in
from django.utils import timezone
from zoneinfo import ZoneInfo

from .models import Profile, LoginVisit  # 👈 LoginVisit model ni previous step lo add chesam

User = get_user_model()
IST = ZoneInfo("Asia/Kolkata")


# 1) New user -> create Profile (mee existing handler)
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.get_or_create(user=instance)


# 2) Successful login -> create one IST-day visit stamp (idempotent)
@receiver(user_logged_in)
def create_daily_login_visit(sender, request, user, **kwargs):
    """
    On every successful login, stamp one row per IST calendar day.
    Unique(user, visit_date) maintains 1/day de-dupe.
    """
    now_ist = timezone.now().astimezone(IST)
    today_ist = now_ist.date()

    # Will no-op if already stamped for today
    LoginVisit.objects.get_or_create(
        user=user,
        visit_date=today_ist,
        defaults={"source": "login"},
    )
