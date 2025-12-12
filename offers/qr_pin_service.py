# qr_pin_service.py   pin generation and verification service
import hashlib
import random
from datetime import timedelta
from django.views.decorators.cache import never_cache, cache_control
from django.views.decorators.csrf import csrf_protect

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





# top lo imports oka sari confirm chesuko
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_protect
from django.http import JsonResponse
from django.utils import timezone
from django.contrib.auth.hashers import make_password
from datetime import timedelta

from .models import Branch, BranchGenerateVisitPin, UserVisitEvent  # BranchGenerateVisitPin model name assume chesina
from django.conf import settings
import random

VISIT_CONFIRM_PIN_TTL = getattr(settings, "VISIT_CONFIRM_PIN_TTL", 1 * 60)  # 2 minutes

def _gen_4_digit_pin() -> str:
    return f"{random.randint(0, 9999):04d}"



@require_POST
@csrf_protect
@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def branch_generate_visit_pin(request):
    """
    STAFF SIDE:
      - Branch_home / QR modal nunchi hit avthundi
      - Branch login (session["branch_id"]) base chesukoni PIN generate chestundi
      - Staff info kuda session nunchi attach cheddam (staff_name, staff_code)
      - User login ('request.user') required kadu
    """

    # ---- 1) Branch session check ----
    branch_id = request.session.get("branch_id")
    if not branch_id:
        return JsonResponse(
            {"ok": False, "error": "Not logged in as a branch."},
            status=403,
        )

    branch = Branch.objects.filter(pk=branch_id).first()
    if not branch:
        return JsonResponse({"ok": False, "error": "Branch not found."}, status=404)

    # ---- 2) Desk + Staff info from session ----
    desk = (
        request.session.get("branch_desk")
        or request.session.get("last_branch_desk")
        or ""
    )

    staff_name = (request.session.get("branch_staff_name") or "").strip()
    staff_code = (request.session.get("branch_staff_code") or "").strip()

    # ⭐ Fallback: branch email tho login ayithe
    # staff_name = "<branch> (BRANCH)" ani snapshot store cheddam
    if not staff_name:
        staff_name = f"{branch.name} (BRANCH)"
        staff_code = ""



    token = ""  # later visit-token attach cheyyali anukunte ikkada set cheyyachu

    now_ts = timezone.now()

    # ---- 3) Old expired pins cleanup (optional but neat) ----
    BranchGenerateVisitPin.objects.filter(
        branch=branch,
        expired=False,
        expires_at__lte=now_ts,
    ).update(expired=True)

    # ---- 4) New PIN generate ----
    pin = _gen_4_digit_pin()
    pin_hash = make_password(pin)
    expires_at = now_ts + timedelta(seconds=VISIT_CONFIRM_PIN_TTL)

    # ---- 5) Visit PIN row create ----
    visit_pin = BranchGenerateVisitPin.objects.create(
        branch=branch,
        desk=desk,
        token=token,
        pin_hash=pin_hash,
        expires_at=expires_at,
        used=False,
        # 🌟 staff attach
        staff_name=staff_name,
        staff_code=staff_code,
    )

    # already_today ippudu *customer-specific* ga calc cheyyalem;
    # branch level info kavali ante later design cheddam.
    already_today = False

    # ---- 6) Frontend ki respond ----
    return JsonResponse(
        {
            "ok": True,
            "pin": pin,  # 👈 modal lo chupinchadaniki
            "branch_name": branch.name,
            "expires_in": VISIT_CONFIRM_PIN_TTL,
            "already_today": already_today,
            # optional: debugging / display kosam staff info kuda pampistunna
            "staff_name": staff_name,
            "staff_code": staff_code,
            "desk": desk,
        }
    )