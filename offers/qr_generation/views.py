# offers/qr_generation/views.py
import hashlib
from django.conf import settings
from django.http import JsonResponse,HttpResponseBadRequest
from django.urls import reverse
from django.shortcuts import redirect
from django.views.decorators.http import require_GET
from django.views.decorators.cache import never_cache, cache_control

from offers.models import Branch
from offers.qr_pin_service import create_qrpin_for_existing_token
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



@require_GET
@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def start_counter_qr(request):
    """
    Generates:
      - signed QR token
      - absolute redeem URL
      - 4-digit PIN (QRPin row)
    
    Returns JSON for frontend modal.
    """
    branch_param = (request.GET.get("branch") or "").strip()
    b = None

    # ---- Resolve branch ----
    if branch_param:
        # Try public_id
        b = Branch.objects.filter(public_id=branch_param).first()

        # Try integer PK
        if b is None and branch_param.isdigit():
            b = Branch.objects.filter(pk=int(branch_param)).first()

        # Try name (case-insensitive)
        if b is None:
            b = Branch.objects.filter(name__iexact=branch_param).first()
    else:
        # Session fallback (branch-login mode)
        bid = request.session.get("branch_id")
        if bid:
            b = Branch.objects.filter(pk=bid).first()

    if not b:
        return JsonResponse({"ok": False, "error": "Branch required/unknown."}, status=400)

    # ---- Desk ----
    desk = (request.GET.get("desk") or getattr(b, "default_desk", "A1") or "A1").strip()[:12]

    # ---- Staff context (from branch_otp_verify session) ----
    staff_name = request.session.get("branch_staff_name") or ""
    staff_code = request.session.get("branch_staff_code") or ""
    staff_id   = request.session.get("branch_staff_id") or None

    # ---- TTL ----
    EXPIRES_IN = int(getattr(settings, "QR_TTL_SECS", 180))

    # ---- 1) Mint QR token ----
    token = mint_qr_token(b.id, desk, EXPIRES_IN)
    payload_url = _abs(request, reverse("qrgen:redeem_land", args=[token]))

    # ---- 2) Create PIN (QRPin row) ----
    qr_data = create_qrpin_for_existing_token(
        branch=b,
        desk=desk,
        token=token,
        ttl_secs=EXPIRES_IN,
        staff_name=staff_name,
        staff_code=staff_code,
    )
    pin = qr_data["pin"]

    # ---- 3) Response ----
    label = f"{b.name} · #{_short_tag(b)}"

    return JsonResponse(
        {
            "ok": True,
            "payload": payload_url,
            "expires_in": EXPIRES_IN,
            "branch": label,
            "desk": desk,
            "branch_public_id": b.public_id,
            "branch_tag": _short_tag(b),
            "pin": pin,
            # ✅ NEW: staff info (optional)
            "staff_name": staff_name,
            "staff_code": staff_code,
            "staff_id": staff_id,
        }
    )



@require_GET
@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def redeem_land(request, token: str):
    try:
        # just verify + decode, kani used unna QR kuda landing ki allow cheddam
        info = parse_qr_token(token, mark_used=False, allow_used=True)
    except ValueError as e:
        return HttpResponseBadRequest(f"Invalid link: {e}")

    b = Branch.objects.filter(pk=info["bid"]).first()
    if not b:
        return HttpResponseBadRequest("Branch not found")

    # (QrLandingEvent / qr_visit_count block already remove chesam)

    # session context
    request.session["branch_id"] = b.id
    request.session["branch_name"] = b.name
    request.session["branch_desk"] = info.get("desk")
    request.session.modified = True

    return redirect(reverse("offers:user_home"))

