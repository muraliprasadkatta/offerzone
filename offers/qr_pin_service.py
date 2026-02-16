# offers/qr_pin_service.py /visit pin generation logic (staff side)
from datetime import timedelta
import random

from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone
from django.contrib.auth.hashers import make_password
from django.views.decorators.cache import never_cache, cache_control
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

from .models import Branch, BranchGenerateVisitPin

VISIT_CONFIRM_PIN_TTL = getattr(settings, "VISIT_CONFIRM_PIN_TTL", 60)  # seconds

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
      - User login required kadu
    """

    # 1) Branch session check
    branch_id = request.session.get("branch_id")
    if not branch_id:
        return JsonResponse({"ok": False, "error": "Not logged in as a branch."}, status=403)

    branch = Branch.objects.filter(pk=branch_id).first()
    if not branch:
        return JsonResponse({"ok": False, "error": "Branch not found."}, status=404)

    # 2) Desk + Staff info from session
    desk = request.session.get("branch_desk") or request.session.get("last_branch_desk") or ""

    staff_name = (request.session.get("branch_staff_name") or "").strip()
    staff_code = (request.session.get("branch_staff_code") or "").strip()

    if not staff_name:
        staff_name = f"{branch.name} (BRANCH)"
        staff_code = ""

    # (optional) token future use
    token = ""

    now_ts = timezone.now()

    # 3) Old expired pins cleanup
    BranchGenerateVisitPin.objects.filter(
        branch=branch,
        expired=False,
        expires_at__lte=now_ts,
    ).update(expired=True,expired_at=now_ts)

    # 4) New PIN generate
    pin = _gen_4_digit_pin()
    pin_hash = make_password(pin)
    expires_at = now_ts + timedelta(seconds=VISIT_CONFIRM_PIN_TTL)

    # 5) Create PIN row
    BranchGenerateVisitPin.objects.create(
        branch=branch,
        desk=desk,
        token=token,
        pin_hash=pin_hash,
        expires_at=expires_at,
        used=False,
        staff_name=staff_name,
        staff_code=staff_code,
    )

    # 6) Response
    return JsonResponse({
        "ok": True,
        "pin": pin,
        "branch_name": branch.name,
        "expires_in": VISIT_CONFIRM_PIN_TTL,
        "already_today": False,
        "staff_name": staff_name,
        "staff_code": staff_code,
        "desk": desk,
    })
