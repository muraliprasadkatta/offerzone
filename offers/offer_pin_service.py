# offers/offer_pin_service.py
from datetime import timedelta
import random

from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone
from django.contrib.auth.hashers import make_password
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.cache import never_cache, cache_control

from offers.models import Branch, OfferDayPin
from offers.services.offer_eligibility_service import build_offer_eligibility_context

OFFER_PIN_TTL = getattr(settings, "OFFER_PIN_TTL", 120)  # seconds


def _gen_4_digit_pin() -> str:
    return f"{random.randint(0, 9999):04d}"


@require_POST
@csrf_protect
@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def user_generate_offer_pin(request):
    """
    USER SIDE:
      - Eligibility preview modal open avvagane hit avthundi
      - Requires user login
      - Requires pending QR context (tied to scan/pin flow)
      - Generates 4-digit PIN (TTL), stores in OfferDayPin
      - Branch staff will verify later
      - Returns offer_pin_id (for user-side polling / redirect)
    """
    if not request.user.is_authenticated:
        return JsonResponse({"ok": False, "error": "login_required"}, status=401)

    # ✅ pending QR context MUST
    pending_token = (request.session.get("pending_qr_token") or "").strip()
    branch_id = request.session.get("pending_qr_branch_id")
    desk = (request.session.get("pending_qr_desk") or "").strip()

    if not pending_token or not branch_id:
        return JsonResponse({"ok": False, "error": "no_pending_qr"}, status=400)

    branch = Branch.objects.filter(pk=branch_id).only("id", "name").first()
    if not branch:
        return JsonResponse({"ok": False, "error": "branch_not_found"}, status=404)

    now_ts = timezone.now()

    # ✅ eligibility check (pending_started required)
    offer_ctx = build_offer_eligibility_context(
        user=request.user,
        branch_id=int(branch_id),
        pending_started=True,
        now_ts=now_ts,
    )

    if not offer_ctx.get("offer_is_active"):
        return JsonResponse({"ok": False, "error": "no_active_offer"}, status=400)

    if not offer_ctx.get("show_check_eligibility"):
        return JsonResponse({"ok": False, "error": "not_eligible"}, status=403)

    # ✅ cleanup: expire old unused pins for this user+branch
    OfferDayPin.objects.filter(
        branch_id=branch.id,
        user_id=request.user.id,
        used=False,
        expires_at__lte=now_ts,
    ).update(used=True, used_at=now_ts)

    # ✅ (optional) prevent spamming: if already have a live unused pin, reuse it
    live = (
        OfferDayPin.objects
        .filter(
            branch_id=branch.id,
            user_id=request.user.id,
            token=pending_token,
            used=False,
            expires_at__gt=now_ts,
        )
        .order_by("-id")
        .first()
    )
    if live:
        # NOTE: we can't return plain pin because it's hashed; so we generate new only if you want pin always visible.
        # To keep behaviour consistent (always show pin), comment this block if not needed.
        # For now: create new each time (so user sees a pin).
        pass

    # ✅ generate new pin
    pin = _gen_4_digit_pin()
    pin_hash = make_password(pin)
    expires_at = now_ts + timedelta(seconds=int(OFFER_PIN_TTL))

    row = OfferDayPin.objects.create(
        branch=branch,
        user=request.user,
        token=pending_token,
        desk=desk,
        pin_hash=pin_hash,
        expires_at=expires_at,
        used=False,
    )

    return JsonResponse({
        "ok": True,
        "pin": pin,
        "offer_pin_id": row.id,                 # ✅ NEW: for polling / auto-redirect
        "expires_in": int(OFFER_PIN_TTL),
        "expires_at_iso": expires_at.isoformat(),  # ✅ helper (optional)
        "branch_name": branch.name,
        "desk": desk,
    })
