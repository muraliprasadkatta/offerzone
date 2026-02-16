# offers/qr_generation and pin/views.py
import hashlib
from datetime import timedelta
from random import randint

from django.conf import settings
from django.http import JsonResponse, HttpResponseBadRequest
from django.urls import reverse
from django.shortcuts import redirect
from django.views.decorators.http import require_GET
from django.views.decorators.cache import never_cache, cache_control
from django.db import transaction
from django.utils import timezone
from django.contrib.auth.hashers import make_password

from offers.models import Branch, QRToken, YashPin
from offers.qr_token_utils import mint_qr_token, parse_qr_token



# ========= low-level helpers =========


def _short_tag(branch: Branch) -> str:
    """
    Stable 6-char tag for UI display.
    Uses branch.public_id or id or name.
    """
    alphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

    src = (
        getattr(branch, "public_id", "") 
        or str(branch.id)
        or branch.name
    ).encode("utf-8")

    h = hashlib.sha256(src).digest()
    n = int.from_bytes(h[:4], "big")

    out = []
    for _ in range(6):
        out.append(alphabet[n % len(alphabet)])
        n //= len(alphabet)
    return "".join(out)


def _abs(request, path: str) -> str:
    return request.build_absolute_uri(path)


# ========= views =========
def QRTokenYashPindataSave(
    *,
    branch,
    desk,
    token,
    pin_hash,
    expires_at,
    staff_name="",
    staff_code="",
):
    """
    ✅ Single place DB save for QR + PIN
    """

    qt = QRToken.objects.create(
        branch=branch,
        desk=desk,
        token=token,
        expires_at=expires_at,
        used=False,
        staff_name=staff_name,
        staff_code=staff_code,
    )

    YashPin.objects.create(
        branch=branch,
        desk=desk,
        qr_token=qt,
        pin_hash=pin_hash,
        expires_at=expires_at,
        used=False,
        staff_name=staff_name,
        staff_code=staff_code,
    )

    return qt




@require_GET
@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
@transaction.atomic
def start_counter_qr(request):

    # ---- resolve branch ----
    branch_param = (request.GET.get("branch") or "").strip()
    b = None

    if branch_param:
        b = Branch.objects.filter(public_id=branch_param).first()
        if b is None and branch_param.isdigit():
            b = Branch.objects.filter(pk=int(branch_param)).first()
        if b is None:
            b = Branch.objects.filter(name__iexact=branch_param).first()
    else:
        bid = request.session.get("branch_id")
        if bid:
            b = Branch.objects.filter(pk=bid).first()

    if not b:
        return JsonResponse({"ok": False, "error": "Branch required/unknown."}, status=400)

    desk = (request.GET.get("desk") or "A1")[:12]

    staff_name = request.session.get("branch_staff_name") or ""
    staff_code = request.session.get("branch_staff_code") or ""
    staff_id   = request.session.get("branch_staff_id")

    EXPIRES_IN = int(getattr(settings, "QR_TTL_SECS", 180))
    expires_at = timezone.now() + timedelta(seconds=EXPIRES_IN)

    # ---- mint token ----
    token = mint_qr_token(b.id, desk, EXPIRES_IN)
    payload_url = request.build_absolute_uri(
        reverse("qrgen:redeem_land", args=[token])
    )

    # ---- pin ----
    pin = f"{randint(0, 9999):04d}"
    pin_hash = make_password(pin)

    # ✅ USE helper
    QRTokenYashPindataSave(
        branch=b,
        desk=desk,
        token=token,
        pin_hash=pin_hash,
        expires_at=expires_at,
        staff_name=staff_name,
        staff_code=staff_code,
    )

    return JsonResponse({
        "ok": True,
        "payload": payload_url,
        "expires_in": EXPIRES_IN,
        "branch": b.name,
        "desk": desk,
        "pin": pin,
        "staff_name": staff_name,
        "staff_code": staff_code,
        "staff_id": staff_id,
    })




def redeem_land(request, token: str):
    try:
        info = parse_qr_token(token)
    except ValueError as e:
        return HttpResponseBadRequest(str(e))

    b = Branch.objects.filter(pk=info["bid"]).first()
    if not b:
        return HttpResponseBadRequest("Branch not found")

    request.session["branch_id"] = b.id
    request.session["branch_name"] = b.name
    request.session["branch_desk"] = info.get("desk")
    request.session.modified = True

    return redirect(reverse("offers:user_home"))




