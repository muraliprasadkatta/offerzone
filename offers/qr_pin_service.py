# qr_pin_service.py
import hashlib
import random
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from django.utils.crypto import get_random_string

from .models import QRPin


def _hash_pin(pin: str, token: str, branch_id: int) -> str:
    """
    PIN ni hash cheyyadaniki helper.
    Token + branch_id + SALT mix chesi hash chestham, so pin alone guess cheyyatam kashhtam.
    """
    salt = getattr(settings, "OZ_QR_PIN_SALT", "oz.qrpin.default.salt")
    raw = f"{pin}:{token}:{branch_id}:{salt}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def create_qrpin_for_existing_token(branch, desk: str, token: str, ttl_secs: int):
    """
    Token already ready undi (e.g. _mint_token nundi ochindi) ani anukoni:
    - 4-digit PIN generate chestundi
    - hash compute chestundi
    - QRPin row create chestundi
    - basic metadata bundle ga return chestundi
    """
    # 1) PIN generate (1000–9999, 4-digit, 0tho start kakunda)
    pin = f"{random.randint(1000, 9999)}"

    # 2) Hash compute
    pin_hash = _hash_pin(pin, token, branch.id)

    # 3) Expiry time
    now = timezone.now()
    expires_at = now + timedelta(seconds=ttl_secs)

    # 4) DB row create
    qrpin = QRPin.objects.create(
        branch=branch,
        desk=desk or "",
        token=token,
        pin_hash=pin_hash,
        expires_at=expires_at,
    )

    # 5) Caller ki result return
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
