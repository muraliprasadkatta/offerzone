# qr_pin_service.py   pin generation and verification service
import hashlib
import random
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from django.utils.crypto import get_random_string

from django.db import transaction   # 👈 add this
from .models import QRPin


def _hash_pin(pin: str, token: str, branch_id: int) -> str:
    salt = getattr(settings, "OZ_QR_PIN_SALT", "oz.qrpin.default.salt")
    raw = f"{pin}:{token}:{branch_id}:{salt}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def create_qrpin_for_existing_token(branch, desk: str, token: str, ttl_secs: int, staff_name: str = "", staff_code: str = "",):
    """
    Token already ready undi (mint_qr_token nundi).
    - 4-digit PIN generate chestundi
    - hash compute chestundi
    - QRPin row ni (token basis lo) create/update chestundi
    - metadata return chestundi
    """
    # 1) 4-digit PIN (1000–9999)
    pin = f"{random.randint(1000, 9999)}"

    # 2) Hash compute
    pin_hash = _hash_pin(pin, token, branch.id)

    # 3) Expiry
    now = timezone.now()
    expires_at = now + timedelta(seconds=ttl_secs)

    # 4) Idempotent create/update by token
    with transaction.atomic():
        qrpin, _created = QRPin.objects.update_or_create(
            token=token,
            defaults={
                "branch": branch,
                "desk": desk or "",
                "pin_hash": pin_hash,
                "expires_at": expires_at,
                "used": False,   # fresh PIN ⇒ not used
                "staff_name": staff_name or "",
                "staff_code": staff_code or "",
            },
        )

    # 5) Return to caller
    return {
        "obj": qrpin,
        "token": token,
        "pin": pin,
        "expires_in": ttl_secs,
        "expires_at": expires_at,
        "branch": branch,
        "desk": desk or "",
    }


def generate_qr_token_and_pin(branch, desk: str = "", ttl_secs: int | None = None):
    """
    Oka fresh QR token + 4-digit PIN create chesthundi,
    DB lo QRPin row create chesi, useful data return chesthundi.

    NOTE:
      - Ikkada token = random 40-char string
      - Expiry/QRPin/PIN logic create_qrpin_for_existing_token reuse chesthundi
    """
    if ttl_secs is None:
        ttl_secs = getattr(settings, "QR_TTL_SECS", 180)

    # ----- 1) Token generate -----
    # unique=True kabatti rare ga conflict vasthe 2–3 tries chestham
    for _ in range(3):
        token = get_random_string(40)  # 40-char random string
        if not QRPin.objects.filter(token=token).exists():
            break

    # ----- 2) PIN + QRPin create (shared helper) -----
    return create_qrpin_for_existing_token(branch, desk, token, ttl_secs)


def verify_qr_pin(qrpin: QRPin, pin_input: str) -> bool:
    """
    Tarvata use avvadaniki: user/staff enter chesina PIN correct aa kadha ani check cheyyadaniki.
    """
    expected_hash = _hash_pin(pin_input, qrpin.token, qrpin.branch_id)
    return expected_hash == qrpin.pin_hash



# offers/qr_generation/views.py

import random
from datetime import timedelta

from django.conf import settings
from django.shortcuts import render
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_POST
from django.views.decorators.cache import never_cache, cache_control
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password

from offers.models import Branch, VisitConfirmPIN, UserVisitEvent  # 👈 new model import (see above)


VISIT_CONFIRM_PIN_TTL = getattr(settings, "VISIT_CONFIRM_PIN_TTL", 5 * 60)  # 5 minutes


def _gen_4_digit_pin() -> str:
    # 0000–9999 or 1000–9999, nenu generic 4-digit istunna
    return f"{random.randint(0, 9999):04d}"


@require_POST
@login_required
@csrf_protect
@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def start_confirm_visit_pin(request):
    """
    Customer side lo 'Confirm Visit' button nunchi hit ayye view.

    Goal:
      - Current user + branch context base chesukoni 4-digit PIN generate cheyyadam
      - Old QRPin system ki asalu touch cheyyakunda, separate VisitConfirmPIN row create cheyyadam
      - PIN ni JSON or template lo return cheyyadam (customer ki chupinchadaniki)

    Later:
      - Branch side lo vere view (branch_views.py) lo
        ee PIN ni verify chesi UserVisitEvent create chestam.
    """

    # ---- 1) Branch context (QR scan / visit intake taruvata) ----
    branch_id = (
        request.session.get("last_branch_id")
        or request.session.get("branch_id")
    )
    if not branch_id:
        return JsonResponse(
            {"ok": False, "error": "Branch context not found. Please scan branch QR first."},
            status=400,
        )

    branch = Branch.objects.filter(pk=branch_id).first()
    if not branch:
        return JsonResponse({"ok": False, "error": "Branch not found."}, status=404)

    desk = request.session.get("last_branch_desk", "") or ""
    token = request.session.get("last_visit_token", "") or ""

    now_ts = timezone.now()

    # (Optional but useful) — same user+branch+today ki already visit recorded aa?
    # actual strict guard ni branch verify side lo kuda pettham, kani ikkada info kosam:
    start_of_day = now_ts.replace(hour=0, minute=0, second=0, microsecond=0)
    already_today = UserVisitEvent.objects.filter(
        user=request.user,
        branch=branch,
        created_at__gte=start_of_day,
    ).exists()

    # ---- 2) 4-digit PIN generate ----
    pin = _gen_4_digit_pin()
    pin_hash = make_password(pin)  # 🔐 No relation to old QRPin hash

    # (Optional) purana unused confirm PINs ni soft-expire cheyyachu (same user+branch)
    VisitConfirmPIN.objects.filter(
        user=request.user,
        branch=branch,
        used=False,
        expires_at__lte=now_ts,
    ).update(used=True)

    # ---- 3) New VisitConfirmPIN row create ----
    expires_at = now_ts + timedelta(seconds=VISIT_CONFIRM_PIN_TTL)

    VisitConfirmPIN.objects.create(
        user=request.user,
        branch=branch,
        desk=desk,
        token=token,
        pin_hash=pin_hash,
        expires_at=expires_at,
        used=False,
    )

    # ---- 4) Return: JSON or modal render ----
    #
    # A) If you want JSON only (SPA style):
    # return JsonResponse({
    #     "ok": True,
    #     "pin": pin,
    #     "branch_name": branch.name,
    #     "expires_in": VISIT_CONFIRM_PIN_TTL,
    #     "already_today": already_today,
    # })
    #
    # B) If you want to render the modal template directly:
    return render(
        request,
        "offers/qr_generation/conform_visitor_pin_modal.html",
        {
            "pin": pin,
            "branch": branch,
            "expires_in": VISIT_CONFIRM_PIN_TTL,
            "already_today": already_today,
        },
    )
