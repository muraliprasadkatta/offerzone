# D:\restarent_application50\offers\services\visit_unit\visit_unit.py
from django.db.models import Q
from django.utils import timezone

from offers.models import ComplementaryOffer

# Allowed visit modes (single source of truth)
ALLOWED_VISIT_UNITS = ("qr_pin", "qr_code")


def get_active_visit_unit(branch_id: int, now_ts=None) -> str:
    """
    Decide the active visit_unit for a branch at this moment.

    Priority:
      1) Branch-specific active offer
      2) Global (all_branches) active offer
      3) Fallback = "qr_pin"

    Returns only values from ALLOWED_VISIT_UNITS.
    """

    if not branch_id:
        return "qr_pin"

    now_ts = now_ts or timezone.now()

    base_qs = (
        ComplementaryOffer.objects
        .filter(
            kind="complementary_offer",
            is_active=True,
            start_at__lte=now_ts,
        )
        .filter(Q(end_at__isnull=True) | Q(end_at__gte=now_ts))
        .only("visit_unit", "all_branches", "start_at", "id")
    )

    # 1️⃣ Branch-specific override (highest priority)
    offer = (
        base_qs
        .filter(all_branches=False, eligible_branches__id=branch_id)
        .order_by("-start_at", "-id")
        .first()
    )

    # 2️⃣ Global fallback
    if not offer:
        offer = (
            base_qs
            .filter(all_branches=True)
            .order_by("-start_at", "-id")
            .first()
        )

    # 3️⃣ Normalize + fallback
    visit_unit = (offer.visit_unit if offer else "qr_pin") or "qr_pin"
    visit_unit = visit_unit.strip()

    return visit_unit if visit_unit in ALLOWED_VISIT_UNITS else "qr_pin"