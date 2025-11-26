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

from .models import Branch, BranchOTP


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
    GET /branch/check?name=...  → {ok: true, exists: bool, email?: "..."}

    Case-insensitive on Branch.name
    """
    name = (request.GET.get("name") or "").strip()
    if not name:
        return JsonResponse({"ok": True, "exists": False})

    obj = Branch.objects.filter(name__iexact=name).only("id", "email").first()
    if not obj:
        return JsonResponse({"ok": True, "exists": False})

    return JsonResponse({
        "ok": True,
        "exists": True,
        "email": (obj.email or ""),
    })


@require_POST
def branch_otp_send(request: HttpRequest):
    """
    IN  : { "branch": "<branchcode>" }
    OUT : { "ok": true } | { "ok": false, "error": "..." }

    Uses Branch.email as the recipient. User OTP flow remains untouched.
    """
    data = _json(request)
    bn = _clean_branch(data.get("branch"))

    if not bn:
        return JsonResponse({"ok": False, "error": "Branch required."}, status=400)

    b = Branch.objects.filter(name__iexact=bn).only("id", "email", "name").first()
    if not b:
        return JsonResponse({"ok": False, "error": "Branch not found."}, status=404)
    if not b.email:
        return JsonResponse({"ok": False, "error": "No email configured for this branch."}, status=400)

    identifier = b.email.strip()
    now = _now()

    # Cooldown
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

    # Window cap
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

    # Send email
    try:
        send_mail(
            subject=f"Branch Login OTP · {b.name}",
            message=(
                f"Your one-time code is {code}. It expires in 5 minutes.\n"
                f"Branch: {b.name}"
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
    IN : { "branch": "madhapura1", "otp": "123456" }
    OUT: { "ok": true, "next": "/branch_home/" }  OR  { "ok": false, "error": "..." }
    """
    data = _json(request)
    bn = _clean_branch(data.get("branch"))
    otp = (data.get("otp") or "").strip()

    if not bn:
        return JsonResponse({"ok": False, "error": "Branch required."}, status=400)
    if not otp:
        return JsonResponse({"ok": False, "error": "Enter OTP."}, status=400)

    # Find branch + its email (recipient)
    b = Branch.objects.filter(name__iexact=bn).only("id", "email", "name").first()
    if not b or not b.email:
        return JsonResponse({"ok": False, "error": "Branch not found."}, status=404)

    identifier = b.email.strip()
    now = _now()

    # Latest, unexpired, unused OTP for this branch email
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

    # ✅ Success: set branch session
    request.session["branch_id"] = b.id
    request.session["branch_name"] = b.name
    request.session.modified = True

    next_url = reverse("offers:branch_home")
    return JsonResponse({"ok": True, "next": next_url})


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
    request.session.modified = True
    return redirect(reverse("offers:branch_login"))
