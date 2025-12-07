# offers/branch_views.py

import json
import re
from datetime import timedelta
from random import randint

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.mail import send_mail
from django.http import HttpRequest, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import cache_control, never_cache
from django.views.decorators.http import require_POST
from .models import Branch,BranchStaff  # 👈 LoginVisit import important
from .models import Branch, BranchOTP, BranchStaff
from django.core.validators import validate_email
from django.core.exceptions import ValidationError




# ===== Config =====

OTP_TTL_SECS = 5 * 60           # 5 minutes
RESEND_COOLDOWN_SEC = 60        # 60s cooldown between sends
RESEND_WINDOW_MINS = 15         # lookback window
RESEND_WINDOW_MAX = 3           # max sends in window
MAX_VERIFY_ATTEMPTS = 5         # max wrong tries for a single OTP
NEXT_URL_AFTER_LOGIN = "/branch_home/"  # (if you want to use it somewhere else)


# ===== Helpers =====

def _now():
    return timezone.now()


def _code6() -> str:
    return f"{randint(0, 999999):06d}"


def _json(req: HttpRequest):
    try:
        return json.loads(req.body.decode("utf-8") or "{}")
    except Exception:
        return {}


def _clean_branch(v: str) -> str:
    # matches your model rule: lowercase, no spaces/specials
    return re.sub(r"[^a-z0-9]", "", (v or "").strip().lower())


# ===== Views =====

@cache_control(no_store=True, no_cache=True, must_revalidate=True)
@never_cache
def branch_login_view(request):
    if request.session.get("branch_id"):
        return redirect("offers:branch_home")

    if request.user.is_authenticated and not getattr(request.user, "is_admin", False):
        return redirect("offers:user_home")

    return render(request, "branch/branch_registration/branch_login.html")



def branch_check_view(request):
    """
    GET /branch/check?name=...  → {ok: true, exists: bool, email?: "...", staff?: [...]}

    Case-insensitive on Branch.name
    """
    name = (request.GET.get("name") or "").strip()
    if not name:
        return JsonResponse({"ok": True, "exists": False})

    branch = Branch.objects.filter(name__iexact=name).only("id", "email", "name").first()
    if not branch:
        return JsonResponse({"ok": True, "exists": False})

    # Staff list for this branch (only staff_id set unna vallu)
    staff_qs = (
        BranchStaff.objects
        .filter(branch=branch)
        .exclude(staff_id__isnull=True)
        .exclude(staff_id="")
        .values("id", "name", "staff_id", "email")  # 🌟 email add chesam
        .order_by("name")
    )

    return JsonResponse({
        "ok": True,
        "exists": True,
        "email": (branch.email or ""),
        "staff": list(staff_qs),
    })
  

@require_POST
def branch_otp_send(request: HttpRequest):
    """
    IN  : { "branch": "<branchcode>", "identifier": "<email>" }
    OUT : { "ok": true } | { "ok": false, "error": "..." }

    identifier:
      - If empty -> uses Branch.email
      - If given -> must match branch email OR a staff email of that branch
    """
    data = _json(request)
    bn = _clean_branch(data.get("branch"))
    raw_identifier = (data.get("identifier") or "").strip()

    if not bn:
        return JsonResponse({"ok": False, "error": "Branch required."}, status=400)

    b = Branch.objects.filter(name__iexact=bn).only("id", "email", "name").first()
    if not b:
        return JsonResponse({"ok": False, "error": "Branch not found."}, status=404)

    # Decide which email to use
    if raw_identifier:
        identifier = raw_identifier
    else:
        if not b.email:
            return JsonResponse(
                {"ok": False, "error": "No email configured for this branch."},
                status=400,
            )
        identifier = b.email.strip()

    # ---- NEW: figure out whether this is branch email or staff email ----
    identifier_norm = identifier.strip().lower()
    staff_obj = None
    allowed = False

    # 1) branch main email match
    if b.email and b.email.strip().lower() == identifier_norm:
        allowed = True
    else:
        # 2) check staff email
        staff_obj = BranchStaff.objects.filter(
            branch=b,
            email__iexact=identifier,
        ).first()
        if staff_obj:
            allowed = True

    if not allowed:
        return JsonResponse(
            {"ok": False, "error": "Email not linked to this branch."},
            status=400,
        )

    now = _now()

    # Cooldown per email identifier
    recent = (
        BranchOTP.objects
        .filter(identifier=identifier, created_at__gte=now - timedelta(seconds=RESEND_COOLDOWN_SEC))
        .order_by("-created_at")
        .first()
    )
    if recent:
        remaining = RESEND_COOLDOWN_SEC - int((now - recent.created_at).total_seconds())
        return JsonResponse(
            {"ok": False, "error": f"Please wait {max(1, remaining)}s before requesting again."},
            status=429,
        )

    # Window cap per email identifier
    since = now - timedelta(minutes=RESEND_WINDOW_MINS)
    if BranchOTP.objects.filter(identifier=identifier, created_at__gte=since).count() >= RESEND_WINDOW_MAX:
        return JsonResponse({"ok": False, "error": "Too many requests. Try later."}, status=429)

    # Generate & store
    code = _code6()
    row = BranchOTP.objects.create(
        identifier=identifier,
        code_hash=make_password(code),
        expires_at=now + timedelta(seconds=OTP_TTL_SECS),
        attempts=0,
        used=False,
        sent_count=1,
    )

    # ---- NEW: subject + extra line based on staff / branch ----
    if staff_obj:
        # staff email ki OTP
        subject = f"Staff Login OTP · {b.name}"
        who_line = f"Staff: {staff_obj.staff_id or ''} {staff_obj.name}".strip()
    else:
        # normal branch login
        subject = f"Branch Login OTP · {b.name}"
        who_line = f"Branch: {b.name}"

    # Send email to chosen identifier
    try:
        send_mail(
            subject=subject,
            message=(
                f"Your one-time code is {code}. It expires in 5 minutes.\n"
                f"{who_line}"
            ),
            from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@example.com"),
            recipient_list=[identifier],
            fail_silently=False,
        )
    except Exception:
        row.delete()
        return JsonResponse({"ok": False, "error": "Failed to send OTP email."}, status=500)

    return JsonResponse({"ok": True})



@require_POST
def branch_otp_verify(request: HttpRequest):
    """
    IN : { "branch": "madhapura1", "otp": "123456", "identifier": "<email>" }
    OUT: { "ok": true, "next": "/branch_home/" }  OR  { "ok": false, "error": "..." }

    identifier:
      - If empty -> falls back to Branch.email
      - If given -> must be branch email or staff email of that branch
    """
    data = _json(request)
    bn = _clean_branch(data.get("branch"))
    otp = (data.get("otp") or "").strip()
    raw_identifier = (data.get("identifier") or "").strip()

    if not bn:
        return JsonResponse({"ok": False, "error": "Branch required."}, status=400)
    if not otp:
        return JsonResponse({"ok": False, "error": "Enter OTP."}, status=400)

    # Find branch
    b = Branch.objects.filter(name__iexact=bn).only("id", "email", "name").first()
    if not b:
        return JsonResponse({"ok": False, "error": "Branch not found."}, status=404)

    # Decide email identifier
    if raw_identifier:
        identifier = raw_identifier.strip()
    else:
        if not b.email:
            return JsonResponse(
                {"ok": False, "error": "No email configured for this branch."},
                status=400,
            )
        identifier = b.email.strip()

    # Validate identifier belongs to this branch (branch mail OR staff mail)
    identifier_norm = identifier.strip().lower()
    allowed = False

    if b.email and b.email.strip().lower() == identifier_norm:
        allowed = True
    else:
        allowed = BranchStaff.objects.filter(
            branch=b, email__iexact=identifier_norm
        ).exists()

    if not allowed:
        return JsonResponse(
            {"ok": False, "error": "Email not linked to this branch."},
            status=400,
        )

    now = _now()

    # Latest, unexpired, unused OTP for this email
    row = (
        BranchOTP.objects
        .filter(identifier=identifier, used=False, expires_at__gte=now)
        .order_by("-created_at")
        .first()
    )

    if not row:
        return JsonResponse({"ok": False, "error": "OTP expired or not found."}, status=400)

    # Too many attempts?
    if (row.attempts or 0) >= MAX_VERIFY_ATTEMPTS:
        return JsonResponse({"ok": False, "error": "Too many attempts. Request a new OTP."}, status=429)

    ok = check_password(otp, row.code_hash)

    # Increment attempts; mark used on success
    row.attempts = (row.attempts or 0) + 1
    if ok:
        row.used = True
    row.save(update_fields=["attempts", "used"])

    if not ok:
        return JsonResponse({"ok": False, "error": "Invalid OTP."}, status=400)

    # ✅ Success
    staff = None
    if not (b.email and b.email.strip().lower() == identifier_norm):
        # staff email ayyochu → fetch staff row
        staff = BranchStaff.objects.filter(
            branch=b,
            email__iexact=identifier_norm
        ).only("id", "name", "staff_id").first()

    # main branch session
    request.session["branch_id"] = b.id
    request.session["branch_name"] = b.name

    # staff session (if staff found)
    if staff:
        request.session["branch_staff_id"] = staff.id
        request.session["branch_staff_name"] = staff.name
        request.session["branch_staff_code"] = staff.staff_id or ""
        print("BRANCH OTP DEBUG set staff:",
              repr(staff.id), repr(staff.name), repr(staff.staff_id))
    else:
        # branch email dvara login ayithe old staff info clear cheddam
        request.session.pop("branch_staff_id", None)
        request.session.pop("branch_staff_name", None)
        request.session.pop("branch_staff_code", None)
        print("BRANCH OTP DEBUG branch login (no staff)")

    request.session.modified = True

    next_url = reverse("offers:branch_home")
    return JsonResponse({"ok": True, "next": next_url})



from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.views.decorators.cache import never_cache
from django.utils import timezone

from .models import Branch, LoginVisit   # 👈 LoginVisit import important


@never_cache
def branch_home_view(request):
    bid = request.session.get("branch_id")
    if not bid:
        return redirect(reverse("offers:branch_login"))

    branch = get_object_or_404(
        Branch.objects.only("id", "name", "public_id"),
        pk=bid,
    )

    return render(
        request,
        "branch/branch_homepage/branch_homepage.html",
        {"branch": branch},
    )




def branch_logout_view(request):
    # only clear branch session keys (auth user session untouched)
    request.session.pop("branch_id", None)
    request.session.pop("branch_name", None)

    # 🌟 staff session fields kuda clear cheddam
    request.session.pop("branch_staff_id", None)
    request.session.pop("branch_staff_name", None)
    request.session.pop("branch_staff_code", None)

    request.session.modified = True
    return redirect(reverse("offers:branch_login"))



import json
from django.views.decorators.http import require_POST
from django.http import JsonResponse

@require_POST
def branch_staff_create_view(request):
    branch_id = request.session.get("branch_id")
    if not branch_id:
        return JsonResponse({"ok": False, "error": "Not logged in as a branch."}, status=403)

    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        return JsonResponse({"ok": False, "error": "Invalid JSON."}, status=400)

    raw_name   = (data.get("staff_name") or "").strip()
    email      = (data.get("staff_email") or "").strip()
    raw_staff_id = (data.get("staff_id") or "").strip()

    if not raw_name or not email or not raw_staff_id:
        return JsonResponse({"ok": False, "error": "Name, email, and staff ID are required."}, status=400)

    # 🔐 normalize & validate staff NAME (uppercase, letters/spaces only, max 12)
    name = raw_name.upper()
    if len(name) > 12 or not all(ch.isalpha() or ch.isspace() for ch in name):
        return JsonResponse(
            {"ok": False, "error": "Staff name must be letters only (A–Z) and max 12 characters."},
            status=400,
        )

    # 🔐 normalize & validate staff ID (max 8 chars, alphanumeric only)
    staff_id = raw_staff_id.upper()
    if len(staff_id) > 8 or not staff_id.isalnum():
        return JsonResponse(
            {"ok": False, "error": "Staff ID must be letters/numbers only, max 8 characters."},
            status=400,
        )

    # 🔐 email validation
    try:
        validate_email(email)
    except ValidationError:
        return JsonResponse(
            {"ok": False, "error": "Invalid email address."},
            status=400,
        )

    # Optional: prevent duplicate staff_id within same branch
    if BranchStaff.objects.filter(branch_id=branch_id, staff_id=staff_id).exists():
        return JsonResponse({"ok": False, "error": "Staff ID already exists in this branch."}, status=400)

    staff = BranchStaff.objects.create(
        branch_id=branch_id,
        name=name,
        email=email,
        staff_id=staff_id,
    )

    return JsonResponse({"ok": True, "id": staff.id})
