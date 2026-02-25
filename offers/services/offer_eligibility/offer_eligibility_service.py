# offers/services/offer_eligibility_service.py for the check box in user interface

from __future__ import annotations

from typing import Any, Dict, List, Optional

from django.db.models import Q
from django.utils import timezone

from offers.models import ComplementaryOffer, UserVisitEvent


def _to_pos_int(v) -> Optional[int]:
    try:
        x = int(v)
        return x if x > 0 else None
    except Exception:
        return None


def _suffix(n: Optional[int]) -> str:
    if not n:
        return "th"
    if 11 <= (n % 100) <= 13:
        return "th"
    return {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")


def build_offer_eligibility_context(
    *,
    branch_id: int,
    user=None,
    now_ts=None,
    pending_started: bool = False,
) -> Dict[str, Any]:
    """
    USER-SIDE single source of truth for:
    - active offer pick for a branch
    - visit counts (logged-in user within branch)
    - milestone/eligibility calculation
    - template helper strings

    ✅ Eligibility UI should appear ONLY after QR scan (pending_started=True)
    """
    if now_ts is None:
        now_ts = timezone.now()

    start_of_day = now_ts.replace(hour=0, minute=0, second=0, microsecond=0)

    # ---------------------------------------------------------
    # Offer pick (latest ACTIVE offer for this branch)
    # ---------------------------------------------------------
    offer = (
        ComplementaryOffer.objects
        .filter(kind="complementary_offer", is_active=True, start_at__lte=now_ts)
        .filter(Q(end_at__isnull=True) | Q(end_at__gte=now_ts))
        .filter(Q(all_branches=True) | Q(eligible_branches__id=branch_id))
        .order_by("-start_at", "-id")
        .first()
    )

    offer_is_active = bool(offer)
    visit_unit = getattr(offer, "visit_unit", None) or "qr_screenshot"

    # ---------------------------------------------------------
    # Visit counts (CONFIRMED ONLY) from UserVisitEvent
    # ---------------------------------------------------------
    qs = UserVisitEvent.objects.filter(branch_id=branch_id)

    if getattr(user, "is_authenticated", False):
        qs = qs.filter(user=user)
    else:
        qs = qs.none()

    total_visits = qs.count()
    today_visits = qs.filter(created_at__gte=start_of_day).count()

    last_obj = qs.order_by("-created_at").first()
    last_visit_dt = last_obj.created_at if last_obj else None
    last_visit = last_visit_dt.strftime("%Y-%m-%d %H:%M") if last_visit_dt else None

    # ---------------------------------------------------------
    # Eligibility + Milestone helpers
    # ---------------------------------------------------------
    next_visit_no = total_visits + 1

    show_check_eligibility = False
    eligibility_title = ""
    eligibility_sub = ""
    eligibility_visit_text = ""
    eligibility_rule_text = ""

    first_milestone = None
    milestones_sorted: List[int] = []
    offer_repeat = False
    nth_int: Optional[int] = None
    extra_nths_int: List[int] = []

    if offer_is_active:
        nth_int = _to_pos_int(getattr(offer, "nth", None))
        offer_repeat = bool(getattr(offer, "repeat", False))

        raw_extra = getattr(offer, "extra_nths", []) or []
        extra_nths_int = [xi for xi in (_to_pos_int(x) for x in raw_extra) if xi]
        extra_set = set(extra_nths_int)

        milestones: List[int] = []
        if nth_int:
            milestones.append(nth_int)
        milestones += extra_nths_int

        milestones_sorted = sorted(set(milestones))
        first_milestone = milestones_sorted[0] if milestones_sorted else None

        main_hit = bool(nth_int and next_visit_no == nth_int)

        repeat_hit = False
        if nth_int and offer_repeat:
            repeat_hit = (next_visit_no % nth_int == 0) and (next_visit_no != nth_int)

        extra_hit = next_visit_no in extra_set

        if main_hit or repeat_hit or extra_hit:
            show_check_eligibility = True
            eligibility_title = "Eligible ✅"
            eligibility_sub = "Ee visit verify chesthe complimentary unlock avvachu mava."
            eligibility_visit_text = f"Next visit number: {next_visit_no}"

            if main_hit:
                eligibility_rule_text = f"Milestone: {nth_int}{_suffix(nth_int)} visit"
            elif extra_hit:
                eligibility_rule_text = f"Extra milestone: {next_visit_no}{_suffix(next_visit_no)} visit"
            else:
                eligibility_rule_text = f"Repeat milestone: every {nth_int}{_suffix(nth_int)} visit"

    # ---------------------------------------------------------
    # UI helper strings
    # ---------------------------------------------------------
    first_milestone_suffix = _suffix(first_milestone) if first_milestone else "th"

    repeat_text = ""
    if offer_repeat and nth_int:
        repeat_text = f"Repeat: every {nth_int}{_suffix(nth_int)} visit"

    milestone_summary = ""
    if milestones_sorted:
        ms = ", ".join(str(x) + _suffix(x) for x in milestones_sorted)
        milestone_summary = f"Milestones: {ms}"
        if repeat_text:
            milestone_summary += f" • {repeat_text}"
    else:
        milestone_summary = repeat_text or ""

    # ✅ user-side: offer UI only after QR scan
    show_offer_ui = bool(offer_is_active and pending_started)

    # ✅ if pending not started, hide eligibility
    if not pending_started:
        show_check_eligibility = False
        eligibility_title = ""
        eligibility_sub = ""
        eligibility_visit_text = ""
        eligibility_rule_text = ""

    return {
        "offer_is_active": offer_is_active,
        "show_offer_ui": show_offer_ui,
        "visit_unit": visit_unit,

        "total_visits": total_visits,
        "today_visits": today_visits,
        "last_visit": last_visit,

        "show_check_eligibility": show_check_eligibility,
        "next_visit_no": next_visit_no,
        "eligibility_title": eligibility_title,
        "eligibility_sub": eligibility_sub,
        "eligibility_visit_text": eligibility_visit_text,
        "eligibility_rule_text": eligibility_rule_text,

        "first_milestone": first_milestone,
        "first_milestone_suffix": first_milestone_suffix,
        "milestones_sorted": milestones_sorted,
        "offer_repeat": offer_repeat,
        "repeat_text": repeat_text,
        "milestone_summary": milestone_summary,
    }
