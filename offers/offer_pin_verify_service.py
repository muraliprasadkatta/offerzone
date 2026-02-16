# offers/offer_pin_verify_service.py
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.cache import never_cache, cache_control
from django.contrib.auth.hashers import check_password
from django.db import transaction, models
from django.db.utils import IntegrityError

from offers.models import OfferDayPin, UserVisitEvent, UserOfferClaim, ComplementaryOffer

@require_POST
@csrf_protect
@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def branch_verify_offer_pin(request):
    branch_id = request.session.get("branch_id")
    if not branch_id:
        return JsonResponse({"ok": False, "error": "branch_login_required"}, status=401)

    pin = (request.POST.get("pin") or "").strip()
    if not pin and request.content_type and "application/json" in request.content_type:
        try:
            import json
            payload = json.loads(request.body.decode("utf-8") or "{}")
            pin = (payload.get("pin") or "").strip()
        except Exception:
            pin = ""

    if not (pin.isdigit() and len(pin) == 4):
        return JsonResponse({"ok": False, "error": "invalid_pin"}, status=400)

    now_ts = timezone.now()

    cand = OfferDayPin.objects.filter(
        branch_id=branch_id,
        used=False,
        expires_at__gt=now_ts,
    ).order_by("-id")[:80]

    match = None
    for row in cand:
        if check_password(pin, row.pin_hash):
            match = row
            break

    if not match:
        return JsonResponse({"ok": False, "error": "pin_not_found_or_expired"}, status=404)

    staff_name = request.session.get("branch_staff_name") or ""
    staff_code = request.session.get("branch_staff_code") or ""

    claim_issued = False
    claim_ids = []

    with transaction.atomic():
        row = OfferDayPin.objects.select_for_update().filter(pk=match.pk).first()
        if not row or row.used or row.expires_at <= now_ts:
            return JsonResponse({"ok": False, "error": "already_used_or_expired"}, status=409)

        row.used = True
        row.used_at = now_ts
        row.used_by_staff_name = staff_name
        row.used_by_staff_code = staff_code
        row.save(update_fields=["used","used_at","used_by_staff_name","used_by_staff_code"])

        ve = UserVisitEvent.objects.create(
            user=row.user,
            branch_id=int(branch_id),
            token=row.token,
            desk=row.desk,
            visit_method="offer_day_pin",
            staff_name=staff_name,
            staff_code=staff_code,
        )

        # ✅ active offer for this branch (all_branches OR eligible_branches)
        offer = (
            ComplementaryOffer.objects
            .filter(is_active=True, start_at__lte=now_ts)
            .filter(models.Q(end_at__isnull=True) | models.Q(end_at__gte=now_ts))
            .filter(models.Q(all_branches=True) | models.Q(eligible_branches__id=int(branch_id)))
            .order_by("-id")
            .distinct()
            .first()
        )

        # count visits after this event
        visit_count = UserVisitEvent.objects.filter(user=row.user, branch_id=int(branch_id)).count()

        hit_main = bool(offer and offer.nth and offer.nth > 0 and (visit_count % offer.nth == 0))
        hit_extra = []
        if offer:
            for ex in (offer.extra_nths or []):
                try:
                    exn = int(ex)
                except Exception:
                    continue
                if exn > 0 and visit_count == exn:
                    hit_extra.append(exn)

        try:
            if offer and hit_main:
                c = UserOfferClaim.objects.create(
                    user=row.user, branch_id=int(branch_id), visit_event=ve, offer=offer,
                    milestone_kind="main", milestone_n=offer.nth,
                    offer_nth=offer.nth or None, offer_repeat=offer.repeat,
                    offer_extra_nths=offer.extra_nths or [],
                    offer_start_at=offer.start_at, offer_end_at=offer.end_at,
                    token=row.token or "", desk=row.desk or "",
                    staff_name=staff_name, staff_code=staff_code,
                )
                claim_ids.append(c.id)
                claim_issued = True

            for exn in hit_extra:
                c = UserOfferClaim.objects.create(
                    user=row.user, branch_id=int(branch_id), visit_event=ve, offer=offer,
                    milestone_kind="extra", milestone_n=exn,
                    offer_nth=offer.nth or None, offer_repeat=offer.repeat,
                    offer_extra_nths=offer.extra_nths or [],
                    offer_start_at=offer.start_at, offer_end_at=offer.end_at,
                    token=row.token or "", desk=row.desk or "",
                    staff_name=staff_name, staff_code=staff_code,
                )
                claim_ids.append(c.id)
                claim_issued = True

        except IntegrityError:
            pass

    return JsonResponse({
        "ok": True,
        "visit_event_id": ve.id,
        "user_id": row.user_id,
        "branch_id": int(branch_id),
        "desk": row.desk,
        "claim_issued": claim_issued,
        "claim_ids": claim_ids,
        "msg": "Offer PIN verified ✅ visit recorded",
    })
