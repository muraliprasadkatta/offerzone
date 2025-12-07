# offers/qr_token_utils.py

import base64
import hashlib
import hmac
import json
import time

from django.conf import settings
from django.utils import timezone

from .models import QRTokenUsage   # 👈 new import


# ------------------------------
# Base64 URL-safe helpers
# ------------------------------
def b64url_encode(data: bytes) -> str:
    """bytes → URL-safe base64 (no padding)"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """URL-safe base64 (no padding) → bytes"""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


# ------------------------------
# HMAC signing (shared)
# ------------------------------
def sign_payload(payload_b64: str) -> str:
    """
    HMAC-SHA256 sign, then base64-url encode.
    """
    key = getattr(settings, "OZ_QR_SIGNING_KEY", settings.SECRET_KEY)
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key

    digest = hmac.new(key_bytes, payload_b64.encode("utf-8"), hashlib.sha256).digest()
    return b64url_encode(digest)


# ------------------------------
# MINT TOKEN  (shared generator)
# ------------------------------
def mint_qr_token(branch_id: int, desk: str, ttl_seconds: int) -> str:
    """
    Create a signed QR token: payload.signature
    payload = {"bid": int, "desk": str, "exp": unix_ts}
    """
    exp = int(time.time()) + int(max(30, ttl_seconds))

    doc = {
        "bid": int(branch_id),
        "desk": (desk or "A1")[:12],
        "exp": exp,
    }

    payload_bytes = json.dumps(doc, separators=(",", ":")).encode("utf-8")
    payload_b64 = b64url_encode(payload_bytes)

    sig = sign_payload(payload_b64)
    return f"{payload_b64}.{sig}"


# ------------------------------
# PARSE / VERIFY TOKEN (+ already-used logic)
# ------------------------------
def parse_qr_token(token: str, *, mark_used: bool = False, allow_used: bool = False) -> dict:
    """
    Verify, decode and return dict: {"bid", "desk", "exp"}

    - Raises ValueError if:
        * bad format
        * bad signature
        * expired
        * already used (if allow_used=False)

    - If mark_used=True, DB lo QRTokenUsage row ni used=True ga mark chesthundi.
    """
    # 1) format
    try:
        payload_b64, sig_b64 = token.split(".", 1)
    except ValueError:
        raise ValueError("Bad token format")

    # 2) signature
    good_sig = sign_payload(payload_b64)
    if not hmac.compare_digest(good_sig, sig_b64):
        raise ValueError("Bad signature")

    # 3) decode payload
    doc = json.loads(b64url_decode(payload_b64))

    # 4) expiry check
    if int(doc.get("exp", 0)) < int(time.time()):
        raise ValueError("Expired")

    bid = int(doc.get("bid"))
    desk = str(doc.get("desk") or "A1")[:12]
    exp = int(doc["exp"])

    # 5) already-used check in DB
    usage, created = QRTokenUsage.objects.get_or_create(token=token)

    if usage.used and not allow_used:
        # QR already taken / used
        raise ValueError("Already used")

    # 6) mark used if asked
    if mark_used and not usage.used:
        usage.used = True
        usage.used_at = timezone.now()
        usage.save(update_fields=["used", "used_at"])

    return {"bid": bid, "desk": desk, "exp": exp}
