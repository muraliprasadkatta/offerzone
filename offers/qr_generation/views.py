# offers/qr_generation/views.py

import base64
import hashlib
import hmac
import json
import time

from django.conf import settings
from django.http import JsonResponse, HttpResponseBadRequest
from django.shortcuts import redirect
from django.urls import reverse
from django.views.decorators.cache import cache_control, never_cache
from django.views.decorators.http import require_GET

from offers.models import Branch
from offers.qr_pin_service import create_qrpin_for_existing_token


# ========= low-level helpers =========


def _b64url(data: bytes) -> str:
    """bytes → URL-safe base64 (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_dec(s: str) -> bytes:
    """URL-safe base64 (no padding) → bytes."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def _sign(data: bytes) -> str:
    """
    HMAC-SHA256 sign, then base64-url encode.
    Key: OZ_QR_SIGNING_KEY else SECRET_KEY.
    """
    key = getattr(settings, "OZ_QR_SIGNING_KEY", settings.SECRET_KEY)
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    digest = hmac.new(key_bytes, data, hashlib.sha256).digest()
    return _b64url(digest)


def _short_tag(branch: Branch) -> str:
    """
    Small stable tag like 6 chars, UI kosam.
    public_id unte danini hash chesi, else id/name.
    """
    src = (
        getattr(branch, "public_id", "")  # public_id unte
        or str(branch.id)                 # else id
        or branch.name                    # fallback name
    ).encode("utf-8")

    h = hashlib.sha256(src).digest()
    n = int.from_bytes(h[:4], "big")
    alphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
    out = []
    for _ in range(6):
        out.append(alphabet[n % len(alphabet)])
        n //= len(alphabet)
    return "".join(out)


def _mint_token(branch_id: int, desk: str, ttl_seconds: int) -> str:
    """
    Token = b64url(json) + "." + b64url(HMAC_SHA256(json))
      json = {"bid": <int>, "desk": "<str>", "exp": <unix_ts>}
    """
    exp = int(time.time()) + int(max(30, ttl_seconds))
    doc = {
        "bid": int(branch_id),
        "desk": (desk or "A1")[:12],
        "exp": exp,
    }
    payload = _b64url(json.dumps(doc, separators=(",", ":")).encode("utf-8"))
    sig = _sign(payload.encode("utf-8"))
    return f"{payload}.{sig}"


def _parse_token(token: str) -> dict:
    """
    Ok aithe {"bid": int, "desk": str, "exp": int} return chestundi.
    Signature / expiry fail ayite ValueError raise chestundi.
    """
    try:
        payload_b64, sig_b64 = token.split(".", 1)
    except ValueError:
        raise ValueError("bad token")

    good_sig = _sign(payload_b64.encode("utf-8"))
    if not hmac.compare_digest(good_sig, sig_b64):
        raise ValueError("bad signature")

    doc = json.loads(_b64url_dec(payload_b64))
    if int(doc.get("exp", 0)) < int(time.time()):
        raise ValueError("expired")

    bid = int(doc.get("bid"))
    desk = str(doc.get("desk") or "A1")[:12]
    return {"bid": bid, "desk": desk, "exp": int(doc["exp"])}


def _abs(request, path: str) -> str:
    return request.build_absolute_uri(path)


# ========= views =========


@require_GET
@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def start_counter_qr(request):
    """
    QR mint cheyyadaniki endpoint.

    IN:
      GET /qrg/start?branch=<public_id|id|name>&desk=A1

      branch ✱:
        - icchakapothe: session["branch_id"] try chestam (branch login case)
        - isthe: public_id → id → name order lo try chestam

    OUT (JSON):
      {
        "ok": true,
        "payload": "<absolute redeem URL>",
        "expires_in": <secs>,
        "branch": "madhapuraa1 · #ABC123",
        "desk": "A1",
        "branch_public_id": "XYZ...",
        "branch_tag": "ABC123",
        "pin": "1234"
      }
    """
    branch_param = (request.GET.get("branch") or "").strip()
    b = None

    # ----- branch resolve -----
    if branch_param:
        # 1) public_id try
        b = Branch.objects.filter(public_id=branch_param).first()
        # 2) pk ayemo ani
        if b is None and branch_param.isdigit():
            b = Branch.objects.filter(pk=int(branch_param)).first()
        # 3) name case-insensitive
        if b is None:
            b = Branch.objects.filter(name__iexact=branch_param).first()
    else:
        # branch login session case
        bid = request.session.get("branch_id")
        if bid:
            b = Branch.objects.filter(pk=bid).first()

    if not b:
        return JsonResponse({"ok": False, "error": "Branch required/unknown."}, status=400)

    desk = (request.GET.get("desk") or getattr(b, "default_desk", "A1") or "A1").strip()[:12]
    EXPIRES_IN = int(getattr(settings, "OZ_QR_EXPIRES_IN", 180))

    # ----- 1) token mint (_mint_token style, HMAC + exp) -----
    token = _mint_token(b.id, desk, EXPIRES_IN)
    payload_url = _abs(request, reverse("qrgen:redeem_land", args=[token]))

    # ----- 2) 4-digit PIN + QRPin row (shared service helper) -----
    qr_data = create_qrpin_for_existing_token(
        branch=b,
        desk=desk,
        token=token,
        ttl_secs=EXPIRES_IN,
    )
    pin = qr_data["pin"]

    # ----- 3) response -----
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
            "pin": pin,  # 👈 frontend modal lo chupinchadaniki (4-digit)
        }
    )


@require_GET
@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def redeem_land(request, token: str):
    """
    GET /qrg/redeem/<token>

    - token parse / verify (HMAC + exp)
    - session lo branch context set
    - user ni user_home ki redirect chestam (later: dedicated redeem page ki marchuko)
    """
    try:
        info = _parse_token(token)
    except ValueError as e:
        return HttpResponseBadRequest(f"Invalid link: {e}")

    b = Branch.objects.filter(pk=info["bid"]).first()
    if not b:
        return HttpResponseBadRequest("Branch not found")

    # session context
    request.session["branch_id"] = b.id
    request.session["branch_name"] = b.name
    request.session["branch_desk"] = info["desk"]
    request.session.modified = True

    return redirect(reverse("offers:user_home"))
