# offers/user_views.py

from datetime import timedelta
from decimal import Decimal, InvalidOperation
import json
import re
import urllib.parse

from django.conf import settings
from django.contrib.auth import get_user_model, login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password
from django.core import signing
from django.core.mail import send_mail
from django.db import transaction, models
from django.db.models.functions import Lower
from django.http import JsonResponse, HttpResponseBadRequest
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache, cache_control
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_protect
from offers.services.offer_eligibility_service import build_offer_eligibility_context
from django.http import JsonResponse
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache, cache_control
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password
from django.http import JsonResponse
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST
from django.views.decorators.cache import never_cache, cache_control
from django.views.decorators.csrf import csrf_protect

from offers.models import QRToken, UserVisitEvent
from offers.qr_token_utils import parse_qr_token as verify_qr_token

import json, re


from .models import (
    QRToken,
    YashPin,
    BranchGenerateVisitPin,
    UserVerifyVisitPin,
    UserVisitEvent,
    Profile,
    Branch,
    LoginOTP,
    UserLocationPing,
    ComplementaryOffer,
    LoginVisit,
)



from .otp_utils import (
    normalize_email,
    valid_email,
    gen_code,
    hash_code,
    expires_at,
    in_cooldown,
    now,
    MAX_RESENDS_PER_15M,
)


# =========================
# Location save helpers
# =========================

def _dec(v, places=6):
    """Convert to Decimal with fixed places; raises on bad input."""
    d = Decimal(str(v))
    return d.quantize(Decimal("1." + "0" * places))


def _in_range(lat, lon):
    return (-90 <= float(lat) <= 90) and (-180 <= float(lon) <= 180)


@login_required
@require_POST
@csrf_protect
def save_location(request):
    """
    JSON Body:
      { "latitude": 17.3850, "longitude": 78.4867, "accuracy": 12, "source": "browser" }
    Stores a ping row; also (optionally) updates Profile last_* if present.
    """
    try:
        body = json.loads(request.body.decode() or "{}")
    except Exception:
        return JsonResponse({"ok": False, "error": "Invalid JSON"}, status=400)

    lat = body.get("latitude")
    lon = body.get("longitude")
    acc = body.get("accuracy")  # optional
    src = (body.get("source") or "browser")[:32]

    if lat is None or lon is None:
        return JsonResponse({"ok": False, "error": "latitude & longitude required"}, status=400)

    try:
        dlat = _dec(lat, 6)
        dlon = _dec(lon, 6)
    except (InvalidOperation, ValueError):
        return JsonResponse({"ok": False, "error": "Invalid coordinates"}, status=400)

    if not _in_range(dlat, dlon):
        return JsonResponse({"ok": False, "error": "Out-of-range coordinates"}, status=400)

    try:
        acc_f = float(acc) if acc is not None else None
        if acc_f is not None and acc_f < 0:
            acc_f = None
    except (TypeError, ValueError):
        acc_f = None

    # 1) Save history row
    row = UserLocationPing.objects.create(
        user=request.user,
        latitude=dlat,
        longitude=dlon,
        accuracy_m=acc_f,
        source=src,
    )

    # 2) (Optional) Update Profile “last_*” if those fields exist
    prof = getattr(request.user, "profile", None)
    if prof is None:
        prof, _ = Profile.objects.get_or_create(user=request.user)

    for fld in ("last_latitude", "last_longitude", "last_loc_accuracy_m", "last_loc_at"):
        if not hasattr(prof, fld):
            break
    else:
        prof.last_latitude = dlat
        prof.last_longitude = dlon
        prof.last_loc_accuracy_m = acc_f
        prof.last_loc_at = timezone.now()
        prof.save(
            update_fields=[
                "last_latitude",
                "last_longitude",
                "last_loc_accuracy_m",
                "last_loc_at",
            ]
        )

    return JsonResponse(
        {
            "ok": True,
            "id": row.id,
            "lat": float(dlat),
            "lon": float(dlon),
            "accuracy_m": acc_f,
            "saved_at": row.created_at.isoformat(),
        }
    )


# =========================
# Public pages
# =========================


@cache_control(no_store=True, no_cache=True, must_revalidate=True)
@never_cache
def user_login_page(request):
    # Branch session active → branch home ki
    if request.session.get("branch_id"):
        return redirect("offers:branch_home")

    # Already authenticated ayithe direct redirect
    if request.user.is_authenticated:
        if request.user.is_superuser:
            return redirect("offers:admin_home")
        return redirect("offers:user_home")

    # Normal GET → login form
    return render(request, "user_registration/user_login.html")


# =========================
# User Home + Name modal flow
# =========================

NAME_RE = re.compile(r"^[^\s].{1,39}$")  # 2–40 chars, Unicode-friendly


def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip



from django.db import models
from django.db.models.functions import Lower
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render


@csrf_protect
@login_required
@csrf_protect
@never_cache
def user_home_page(request):
    # Superusers shouldn’t see user home
    if request.user.is_superuser:
        return redirect("offers:admin_home")

    client_ip = get_client_ip(request)
    ua = request.META.get("HTTP_USER_AGENT", "")

    today = timezone.localdate()

    # ✅ daily login stamp
    LoginVisit.objects.update_or_create(
        user=request.user,
        visit_date=today,
        defaults={
            "source": "login",
            "ip_address": client_ip,
            "user_agent": ua,
        },
    )

    now_ts = timezone.now()
    start_of_day = now_ts.replace(hour=0, minute=0, second=0, microsecond=0)

    # ✅ ONE-PER-DAY global flag (any branch today)
    already_claimed_today = UserVisitEvent.objects.filter(
        user=request.user,
        created_at__gte=start_of_day,
    ).exists()

    # Profile
    prof = getattr(request.user, "profile", None)
    if prof is None:
        prof, _ = Profile.objects.get_or_create(user=request.user)

    disp = (prof.display_name or "").strip()
    need_name = (disp == "")

    # Branches for “Branches” card
    LIMIT = 12
    all_branches_qs = Branch.objects.order_by(Lower("name"))
    branch_count = all_branches_qs.count()

    # We still take first LIMIT for now (then reorder within these)
    branches = list(all_branches_qs[:LIMIT])

    # =====================================================
    # ✅ PER-BRANCH active offer start/end (for each tile)
    # =====================================================
    branch_ids = [b.id for b in branches]
    offers_by_branch = {}  # {branch_id: {"start": dt, "end": dt|None}}

    if branch_ids:
        now = now_ts  # reuse

        active_offer_qs = (
            ComplementaryOffer.objects
            .filter(
                kind="complementary_offer",
                is_active=True,
                start_at__lte=now,
            )
            .filter(models.Q(end_at__isnull=True) | models.Q(end_at__gte=now))
            .filter(
                models.Q(all_branches=True) |
                models.Q(eligible_branches__id__in=branch_ids)
            )
            .distinct()
            .order_by("-start_at", "-id")
            .only("id", "start_at", "end_at", "all_branches")
        )

        # 1) latest global offer applies to all branches
        global_offer = (
            active_offer_qs
            .filter(all_branches=True)
            .order_by("-start_at", "-id")
            .first()
        )
        if global_offer:
            for bid in branch_ids:
                offers_by_branch[bid] = {
                    "start": global_offer.start_at,
                    "end": global_offer.end_at,
                }

        # 2) override with latest branch-specific offers
        specific_qs = (
            ComplementaryOffer.objects
            .filter(
                kind="complementary_offer",
                is_active=True,
                start_at__lte=now,
            )
            .filter(models.Q(end_at__isnull=True) | models.Q(end_at__gte=now))
            .filter(all_branches=False, eligible_branches__id__in=branch_ids)
            .values("eligible_branches__id", "start_at", "end_at", "id")
            .order_by("eligible_branches__id", "-start_at", "-id")
        )

        seen = set()
        for row in specific_qs:
            bid = row["eligible_branches__id"]
            if bid in seen:
                continue
            offers_by_branch[bid] = {"start": row["start_at"], "end": row["end_at"]}
            seen.add(bid)

    # attach offer info to branch objects
    for b in branches:
        info = offers_by_branch.get(b.id) or {}
        b.offer_start = info.get("start")
        b.offer_end = info.get("end")

    # =====================================================
    # ✅ ACTIVE FIRST, INACTIVE LAST (single grid reorder)
    # =====================================================
    active_branches = [b for b in branches if b.offer_start]
    inactive_branches = [b for b in branches if not b.offer_start]
    branches = active_branches + inactive_branches
    # =====================================================

    return render(
        request,
        "user_interface/user_homepage.html",
        {
            "need_name": need_name,
            "display_name": disp,
            "branch_count": branch_count,
            "branches": branches,
            "branches_has_more": branch_count > LIMIT,
            "client_ip": client_ip,

            # 🔥 already claimed today?
            "oz_already_claimed_today": already_claimed_today,
        },
    )


@login_required
@require_POST
@csrf_protect
def save_display_name(request):
    try:
        body = json.loads(request.body.decode() or "{}")
    except Exception:
        return JsonResponse({"ok": False, "error": "Invalid JSON"}, status=400)

    name = (body.get("display_name") or "").strip()
    if not (2 <= len(name) <= 40) or not NAME_RE.match(name):
        return JsonResponse({"ok": False, "error": "Enter a valid name (2–40 chars)."}, status=400)

    prof = getattr(request.user, "profile", None)
    if prof is None:
        prof, _ = Profile.objects.get_or_create(user=request.user)

    prof.display_name = name
    prof.save(update_fields=["display_name"])
    request.user.first_name = name
    request.user.save(update_fields=["first_name"])

    return JsonResponse({"ok": True, "name": name})


# =========================
# Email OTP send
# =========================

@require_POST
@csrf_protect
@never_cache
def otp_send(request):
    # Expect JSON: {"email": "..."}
    try:
        body = json.loads(request.body.decode() or "{}")
    except Exception:
        return HttpResponseBadRequest("Invalid JSON")

    email = normalize_email(body.get("email"))
    if not valid_email(email):
        return JsonResponse({"ok": False, "error": "Invalid email."}, status=400)

    # most recent in last 15m
    recent = (
        LoginOTP.objects.filter(email=email, created_at__gte=now() - timedelta(minutes=15))
        .order_by("-created_at")
        .first()
    )

    if recent:
        cooling, wait = in_cooldown(recent.last_sent_at)
        if cooling:
            return JsonResponse(
                {"ok": False, "error": f"Too many requests. Try again in {wait}s."},
                status=429,
            )
        if recent.sent_count >= MAX_RESENDS_PER_15M:
            return JsonResponse(
                {"ok": False, "error": "Too many requests. Try again later."},
                status=429,
            )

        code = gen_code()
        recent.code_hash = hash_code(email, code)
        recent.expires_at = expires_at()
        recent.sent_count += 1
        recent.last_sent_at = now()
        recent.used = False
        recent.attempts = 0
        recent.save()

        _send_email_otp(email, code)
        return JsonResponse({"ok": True, "message": "OTP sent", "resend_after_sec": 60})

    # fresh row
    code = gen_code()
    LoginOTP.objects.create(
        email=email,
        code_hash=hash_code(email, code),
        expires_at=expires_at(),
        attempts=0,
        used=False,
        sent_count=1,
        last_sent_at=now(),
    )
    _send_email_otp(email, code)
    return JsonResponse({"ok": True, "message": "OTP sent", "resend_after_sec": 60})


def _send_email_otp(email: str, code: str):
    subject = "Your sign-in code"
    body = (
        f"Hi,\n\nYour one-time sign-in code is {code}.\n"
        f"It expires in 5 minutes. Do not share this code.\n\n"
        f"If you didn’t request this, please ignore this email."
    )
    send_mail(subject, body, None, [email], fail_silently=False)


# =========================
# Email OTP verify
# =========================

MAX_VERIFY_ATTEMPTS = 5


def _safe_next_from_request(request, body=None):
    default = reverse("offers:user_home")
    candidate = (
        (body or {}).get("next")
        or request.POST.get("next")
        or request.GET.get("next")
        or default
    )

    if not url_has_allowed_host_and_scheme(
        url=candidate, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return default

    # Only superusers can be sent to /admin...
    if (not request.user.is_superuser) and str(candidate).startswith("/admin"):
        return default

    return candidate


@require_POST
@csrf_protect
@never_cache
def otp_verify(request):
    try:
        body = json.loads(request.body.decode() or "{}")
    except Exception:
        return HttpResponseBadRequest("Invalid JSON")

    email = normalize_email(body.get("email"))
    code = (body.get("code") or "").strip()

    if not valid_email(email):
        return JsonResponse({"ok": False, "error": "Invalid email."}, status=400)
    if not (len(code) == 6 and code.isdigit()):
        return JsonResponse({"ok": False, "error": "Enter a valid 6-digit code."}, status=400)

    row = (
        LoginOTP.objects.filter(email=email, created_at__gte=now() - timedelta(minutes=15))
        .order_by("-created_at")
        .first()
    )
    if not row:
        return JsonResponse({"ok": False, "error": "No active code. Please resend."}, status=400)

    if row.used:
        return JsonResponse({"ok": False, "error": "Code already used. Please resend."}, status=400)
    if row.expires_at <= now():
        return JsonResponse({"ok": False, "error": "Code expired. Please resend."}, status=400)
    if row.attempts >= MAX_VERIFY_ATTEMPTS:
        return JsonResponse(
            {"ok": False, "error": "Too many attempts. Please resend a new code."},
            status=429,
        )

    if row.code_hash != hash_code(email, code):
        row.attempts += 1
        row.save(update_fields=["attempts"])
        return JsonResponse({"ok": False, "error": "Incorrect code."}, status=400)

    # success → consume + login
    row.used = True
    row.save(update_fields=["used"])

    User = get_user_model()
    username_default = email.split("@")[0]
    user, _ = User.objects.get_or_create(
        email=email,
        defaults={"username": username_default},
    )
    login(request, user)

    # ensure profile exists on first user login
    Profile.objects.get_or_create(user=user, defaults={"display_name": ""})

    dest = _safe_next_from_request(request, body=body)
    return JsonResponse({"ok": True, "next": dest})


# =========================
# Logout (user)
# =========================

def user_logout_view(request):
    auth_logout(request)
    return redirect("offers:user_login")


# =========================
# QR token generaton helpers (scan / visit count)
# =========================



from offers.qr_token_utils import parse_qr_token as verify_qr_token


TOKEN_PATH_RE = re.compile(r"/qrg/(?:redeem|t)/(?P<tok>[^/?#]+)")


def extract_qr_token_from_raw(raw):
    """
    Try to extract the actual token from a raw string:
    - full URL with /qrg/redeem/<token> or /qrg/t/<token>
    - or plain token-looking string.
    """
    raw = (raw or "").strip()
    if not raw:
        return None

    # 1) If it's a full URL, parse path
    try:
        u = urllib.parse.urlparse(raw)
        if u.scheme and u.netloc:
            m = TOKEN_PATH_RE.search(u.path)
            if m:
                return m.group("tok")
            if "/qrg/redeem/" in u.path:
                return u.path.split("/qrg/redeem/", 1)[1].split("/", 1)[0]
    except Exception:
        pass

    # 2) Otherwise, if it looks like a token already, accept it
    if re.fullmatch(r"[A-Za-z0-9._\-:]+", raw):
        return raw

    return None


SIGN_SALT = "oz.complementary.qr"   # renamed from oz.freeplate.qr


from django.conf import settings

def verify_legacy_colon_token(token: str):
    try:
        ttl = getattr(settings, "QR_TTL_SECS", 180)
        data = signing.loads(
            token,
            salt=SIGN_SALT,
            max_age=ttl + 30
        )
        return {
            "bid": int(data.get("branch")),
            "desk": str(data.get("desk") or "A1"),
            "exp": int(data.get("iat", 0)) + int(data.get("ttl", 0)),
        }
    except Exception as e:
        raise ValueError(f"Legacy token invalid: {e}")


# =========================
# PIN verify (QR PIN)
# =========================


from offers.services.visit_unit.visit_unit import get_active_visit_unit
from offers.services.visit_unit.visit_confirm import (
    confirm_qr_code_visit,
    confirm_qr_code_visit_with_yashpin,
    clear_pending_qr_session,
    set_last_branch_session,
)


PIN_LEN = 4  # 4-digit


@login_required
@require_POST
@never_cache
@csrf_protect
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def pin_verify(request):
    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        data = {}

    raw_pin = str(data.get("pin") or "").strip()
    pin = re.sub(r"\D", "", raw_pin)[:PIN_LEN]

    if not re.fullmatch(rf"\d{{{PIN_LEN}}}", pin):
        return JsonResponse({"ok": False, "error": "Enter a valid 4-digit PIN."}, status=400)

    now_ts = timezone.now()
    start_of_day = now_ts.replace(hour=0, minute=0, second=0, microsecond=0)

    # ✅ small perf hint: try last branch first (but MUST fallback)
    branch_hint = request.session.get("last_branch_id") or request.session.get("pending_qr_branch_id")

    base_qs = (
        YashPin.objects
        .select_related("qr_token", "branch")
        .filter(expires_at__gte=now_ts, used=False)
        .order_by("-created_at")
    )

    def _find_match(qs, limit=80):
        for row in qs[:limit]:
            if check_password(pin, row.pin_hash):
                return row
        return None

    matched = None

    # 1) try branch hint first
    if branch_hint:
        matched = _find_match(base_qs.filter(branch_id=branch_hint), limit=80)

    # 2) fallback global
    if not matched:
        matched = _find_match(base_qs, limit=120)

    if not matched:
        return JsonResponse({"ok": False, "error": "Invalid or expired PIN."}, status=400)

    # ✅ Early clear: if QRToken already used, don’t proceed
    if matched.qr_token.used:
        return JsonResponse(
            {"ok": False, "error": "This PIN is already used. Please ask staff for a new PIN."},
            status=400,
        )

    # ✅ same-day check (per-branch)
    already = UserVisitEvent.objects.filter(
        user=request.user,
        branch=matched.branch,
        created_at__gte=start_of_day,
    ).exists()
    if already:
        return JsonResponse({
            "ok": True,
            "already_claimed_today": True,
            "next": reverse("offers:user_status"),
        })

    # ✅ light attempt tracking
    try:
        matched.attempts = (matched.attempts or 0) + 1
        matched.last_attempt_at = now_ts
        matched.save(update_fields=["attempts", "last_attempt_at"])
    except Exception:
        pass

    # ✅ set branch context
    request.session["last_branch_id"] = matched.branch_id
    request.session["last_branch_name"] = matched.branch.name
    request.session["last_branch_desk"] = matched.desk or ""

    # =====================================================
    # ✅ NEW: if branch visit_unit is qr_code => confirm immediately
    # =====================================================
    vu = get_active_visit_unit(matched.branch_id, now_ts=now_ts)

    if vu == "qr_code":
        res = confirm_qr_code_visit_with_yashpin(
            user=request.user,
            yashpin_id=matched.id,
            now_ts=now_ts,
            used_via="pin",
        )

        if not res.ok:
            return JsonResponse({"ok": False, "error": res.error or "Unable to confirm visit."}, status=400)

        if res.already_claimed_today:
            return JsonResponse({
                "ok": True,
                "already_claimed_today": True,
                "next": reverse("offers:user_status"),
            })

        # ✅ clear any pending locks (safety)
        for k in (
            "pending_qr_token",
            "pending_qr_branch_id",
            "pending_qr_branch_name",
            "pending_qr_desk",
            "pending_qr_started_at",
            "pending_pin_row_id",
            "pending_qr_method",
        ):
            request.session.pop(k, None)

        # ✅ success: go status directly (NO PIN modal)
        return JsonResponse({
            "ok": True,
            "already_claimed_today": False,
            "next": reverse("offers:user_status"),
        })

    # =====================================================
    # ✅ NORMAL FLOW: qr_pin => keep your pending lock + go PIN modal
    # =====================================================

    request.session["pending_qr_token"] = matched.qr_token.token
    request.session["pending_qr_method"] = "pin"
    request.session["pending_pin_row_id"] = matched.id
    request.session["pending_qr_branch_name"] = matched.branch.name
    request.session["pending_qr_branch_id"] = matched.branch_id
    request.session["pending_qr_desk"] = matched.desk or ""
    request.session["pending_qr_started_at"] = now_ts.isoformat()

    return JsonResponse({
        "ok": True,
        "already_claimed_today": False,
        "next": reverse("offers:user_visit_pin_page"),
    })




@login_required
@require_POST
@never_cache
@csrf_protect
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def scan_verify(request):
    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        data = {}

    raw_input = str(data.get("token") or "").strip()
    if not raw_input:
        return JsonResponse({"ok": False, "error": "No token provided."}, status=400)

    token = extract_qr_token_from_raw(raw_input)
    if not token:
        return JsonResponse({"ok": False, "error": "Invalid QR token format."}, status=400)

    # ✅ verify signed token validity
    try:
        _ = verify_qr_token(token)
    except ValueError as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=400)

    now_ts = timezone.now()

    qt = (
        QRToken.objects
        .select_related("branch")
        .filter(token=token)
        .first()
    )
    if not qt:
        return JsonResponse({"ok": False, "error": "QR not found. Please generate again."}, status=400)

    if qt.expires_at and qt.expires_at <= now_ts:
        return JsonResponse({"ok": False, "error": "QR expired."}, status=400)

    # ✅ quick same-day check (still final confirm does it again)
    if request.user.is_authenticated:
        start_of_day = now_ts.replace(hour=0, minute=0, second=0, microsecond=0)
        already = UserVisitEvent.objects.filter(
            user=request.user,
            branch_id=qt.branch_id,
            created_at__gte=start_of_day,
        ).exists()
        if already:
            return JsonResponse({
                "ok": True,
                "already_claimed_today": True,
                "next": reverse("offers:user_status"),
            })

    # ✅ Decide mode from DB (offer.visit_unit)
    vu = get_active_visit_unit(qt.branch_id, now_ts=now_ts)

    # =====================================================
    # ✅ QR CODE MODE => Confirm immediately (skip PIN modal)
    # =====================================================
    if vu == "qr_code":
        res = confirm_qr_code_visit(
            user=request.user,
            token=qt.token,
            used_via="scan",
            now_ts=now_ts,
        )
        if not res.ok:
            return JsonResponse({"ok": False, "error": res.error}, status=400)

        # session updates
        clear_pending_qr_session(request)
        set_last_branch_session(
            request,
            branch_id=qt.branch_id,
            branch_name=qt.branch.name,
            token=qt.token,
            desk=qt.desk or "",
        )

        return JsonResponse({
            "ok": True,
            "already_claimed_today": res.already_claimed_today,
            "next": reverse("offers:user_status"),
        })

    # =====================================================
    # ✅ QR PIN MODE => Keep your existing pending lock flow
    # =====================================================
    request.session["pending_qr_token"] = qt.token
    request.session["pending_qr_method"] = "scan"
    request.session["pending_qr_branch_id"] = qt.branch_id
    request.session["pending_qr_desk"] = qt.desk or ""
    request.session["pending_qr_started_at"] = now_ts.isoformat()
    request.session["pending_qr_branch_name"] = qt.branch.name

    # (optional UI helpers)
    request.session["last_branch_id"] = qt.branch_id
    request.session["last_branch_name"] = qt.branch.name
    request.session["last_branch_desk"] = qt.desk or ""

    return JsonResponse({
        "ok": True,
        "already_claimed_today": False,
        "next": reverse("offers:user_visit_pin_page"),
    })




@login_required
@require_POST
@csrf_protect
@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def confirm_branch_visit(request):
    """
    FINAL step:
    - For scan flow: called after screenshot upload success.
    - For pin flow: call this when user confirms (no screenshot needed) OR you can call same endpoint.
    """

    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        data = {}

    token = (data.get("token") or "").strip() or request.session.get("pending_qr_token")
    if not token:
        return JsonResponse({"ok": False, "error": "No pending QR. Please scan again."}, status=400)

    # hard session match
    if token != request.session.get("pending_qr_token"):
        return JsonResponse({"ok": False, "error": "Session mismatch. Please scan again."}, status=400)

    now_ts = timezone.now()

    pending_method = request.session.get("pending_qr_method") or "scan"
    pending_pin_row_id = request.session.get("pending_pin_row_id")  # only for pin-flow

    with transaction.atomic():
        qt = (
            QRToken.objects
            .select_for_update()
            .select_related("branch")
            .filter(token=token)
            .first()
        )
        if not qt:
            return JsonResponse({"ok": False, "error": "QR not found. Please scan again."}, status=400)

        if qt.expires_at <= now_ts:
            return JsonResponse({"ok": False, "error": "QR expired. Please scan again."}, status=400)

        if qt.used:
            return JsonResponse({"ok": False, "error": "QR already used."}, status=400)

        # ✅ real one-per-day enforcement here (final gate)
        start_of_day = now_ts.replace(hour=0, minute=0, second=0, microsecond=0)
        already = UserVisitEvent.objects.filter(
            user=request.user,
            branch=qt.branch,
            created_at__gte=start_of_day,
        ).exists()
        if already:
            return JsonResponse({
                "ok": True,
                "already_claimed_today": True,
                "redirect_url": reverse("offers:user_visit_pin_page"),
            })

        staff_name = qt.staff_name or ""
        staff_code = qt.staff_code or ""
        desk = qt.desk or ""

        # ✅ If PIN flow → burn YashPin also, and take staff/desk from pin row
        if pending_method == "pin" and pending_pin_row_id:
            pin_row = (
                YashPin.objects
                .select_for_update()
                .select_related("branch")
                .filter(pk=pending_pin_row_id)
                .first()
            )
            if not pin_row:
                return JsonResponse({"ok": False, "error": "PIN session expired. Please re-enter PIN."}, status=400)

            # safety: same token + not expired + not used
            if pin_row.used or pin_row.expires_at < now_ts:
                return JsonResponse({"ok": False, "error": "PIN expired. Please re-enter PIN."}, status=400)

            if pin_row.qr_token_id != qt.id:
                return JsonResponse({"ok": False, "error": "PIN mismatch. Please re-enter PIN."}, status=400)

            # burn pin
            pin_row.used = True
            pin_row.used_at = now_ts
            pin_row.save(update_fields=["used", "used_at"])

            # prefer staff/desk from pin
            staff_name = pin_row.staff_name or staff_name
            staff_code = pin_row.staff_code or staff_code
            desk = pin_row.desk or desk

        # ✅ burn QRToken + create UserVisitEvent
        qt.used = True
        qt.used_at = now_ts
        qt.used_via = "pin" if pending_method == "pin" else "scan"
        qt.used_by = request.user
        qt.save(update_fields=["used", "used_at", "used_via", "used_by"])

        UserVisitEvent.objects.create(
            user=request.user,
            branch=qt.branch,
            token=qt.token,
            desk=desk,
            visit_method="qr_pin" if pending_method == "pin" else "qr_screenshot",
            staff_name=staff_name,
            staff_code=staff_code,
        )

    # ✅ confirmed session for status page
    request.session["last_branch_id"] = qt.branch_id
    request.session["last_branch_name"] = qt.branch.name
    request.session["last_qr_ok_at"] = now_ts.isoformat()
    request.session["last_branch_desk"] = qt.desk or ""
    request.session["last_visit_token"] = qt.token

    # ✅ clear pending (include pin extras also)
    for k in (
        "pending_qr_token",
        "pending_qr_branch_id",
        "pending_qr_desk",
        "pending_qr_started_at",
        "pending_pin_row_id",
        "pending_qr_method",
    ):
        request.session.pop(k, None)

    return JsonResponse({
        "ok": True,
        "already_claimed_today": False,
        "redirect_url": reverse("offers:user_visit_pin_page"),
    })

# ============================================
# branch offers  view in user interface
# =============================================

from django.db.models import Max
from django.utils import timezone
from offers.services.offers_progress_modal_helper import offers_progress_modal_context


def branch_offers_in_userinterface(request, branch_id):
    branch = get_object_or_404(Branch, id=branch_id)
    
    # ✅ force context for pin page / eligibility
    request.session["last_branch_id"] = branch.id
    request.session["last_branch_name"] = branch.name


    now = timezone.now()
    start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)

    base_qs = (
        ComplementaryOffer.objects
        .filter(is_active=True, start_at__lte=now)
        .filter(models.Q(all_branches=True) | models.Q(eligible_branches=branch))
        .distinct()
    )

    offers = base_qs.order_by("id")

    free_plate_offer = base_qs.filter(kind="complementary_offer").order_by("-start_at", "-id").first()


    # =====================================================
    # ✅ NEW: This branch visit stats (only this branch)
    # =====================================================
    branch_total_visits = 0
    branch_today_visits = 0
    branch_last_visit = None
    branch_has_visited = False

    if request.user.is_authenticated:
        vqs = UserVisitEvent.objects.filter(user=request.user, branch=branch)
        branch_total_visits = vqs.count()
        branch_today_visits = vqs.filter(created_at__gte=start_of_day).count()
        branch_last_visit = vqs.aggregate(last=Max("created_at"))["last"]
        branch_has_visited = branch_total_visits > 0
    # =====================================================

    context = {
        "branch": branch,
        "offers": offers,
        "active_offer_count": offers.count(),
        "is_open_now": True,
        "free_plate_offer": free_plate_offer,

        # send to template
        "branch_total_visits": branch_total_visits,
        "branch_today_visits": branch_today_visits,
        "branch_last_visit": branch_last_visit,
        "branch_has_visited": branch_has_visited,
    }
        #  MILESTONE PROGRESS LOGIC HERE
    max_preview = 60
    if free_plate_offer and free_plate_offer.start_at and free_plate_offer.end_at:
        window_days = (free_plate_offer.end_at.date() - free_plate_offer.start_at.date()).days + 1
        max_preview = max(15, min(60, window_days))
        
        progress = offers_progress_modal_context(
            total_visits=branch_total_visits,
            nth=getattr(free_plate_offer, "nth", None),
            repeat=bool(getattr(free_plate_offer, "repeat", True)),
            extra_nths=getattr(free_plate_offer, "extra_nths", []) or [],
            max_preview=max_preview,                 # ✅ dynamic
            include_repeat_multiples=True,           # ✅ repeats show 10/15/20...
        )
        context.update(progress)

    return render(
        request,
        "user_interface/branch_offers_in_userinterface/branch_offers_in_userinterface.html",
        context,
    )


# =========================
# Visit count page after sucefull pin or scan redirect view 
# =========================


from django.views.decorators.cache import cache_control
from django.shortcuts import redirect
from django.utils import timezone
from django.db import models

@cache_control(no_store=True, no_cache=True, must_revalidate=True)
@never_cache
def user_visit_intake_redirect_view(request):
    token = request.GET.get("token")
    if not token:
        return redirect("offers:user_visit_pin_page")

    try:
        # verify token format (signed token check)
        if "." in token:
            info = verify_qr_token(token)
        elif ":" in token:
            info = verify_legacy_colon_token(token)
        else:
            raise ValueError("Bad token format")

        branch = (
            Branch.objects
            .filter(pk=info["bid"])
            .only("id", "name")
            .first()
        )
        if not branch:
            raise ValueError("Branch not found")

        desk = info.get("desk")

        # ✅ ONLY PENDING context (NOT confirmed)
        request.session["pending_qr_branch_id"] = branch.id
        request.session["pending_qr_desk"] = str(desk or "")
        request.session["pending_qr_started_at"] = timezone.now().isoformat()
        request.session["pending_qr_token"] = token  # keep token

        # show same page/modal again (user will confirm next)
        return redirect("offers:user_visit_pin_page")

    except ValueError:
        return redirect("offers:user_home")



from django.db.models import Q
from django.views.decorators.cache import cache_control, never_cache
from django.shortcuts import redirect, render
from django.utils import timezone

from django.db.models import Q
from django.views.decorators.cache import cache_control, never_cache
from django.shortcuts import redirect, render
from django.utils import timezone

@cache_control(no_store=True, no_cache=True, must_revalidate=True)
@never_cache
def user_visit_pin_page_view(request):
    # ✅ Allow both confirmed + pending branch context
    branch_id = request.session.get("last_branch_id") or request.session.get("pending_qr_branch_id")
    if not branch_id:
        return redirect("offers:user_home")

    branch_name = (
        request.session.get("last_branch_name")
        or request.session.get("pending_qr_branch_name")
        or "Unknown Branch"
    )

    # ✅ Pending indicator (scan/pin start?)
    pending_token = (request.session.get("pending_qr_token") or "").strip()
    pending_started = bool(pending_token)

    # ✅ Core offer+eligibility context (single source of truth)
    offer_ctx = build_offer_eligibility_context(
        user=request.user,
        branch_id=branch_id,
        pending_started=pending_started,
    )

    ctx = {
        "branch_name": branch_name,
        "token": request.session.get("last_visit_token") or pending_token,
        "pending_started": pending_started,
        **offer_ctx,
    }

    return render(
        request,
        "user_interface/user_visit_count/user_visit_pin_verify_modal.html",
        ctx,
    )


from django.utils import timezone
from django.db import models
from django.db.models import Count, Max
from django.shortcuts import render

from .models import UserVisitEvent, ComplementaryOffer, Branch


def _parse_iso_dt(v):
    """
    Safe ISO parse for session stored datetime string.
    Returns aware datetime or None.
    """
    if not v:
        return None
    try:
        dt = timezone.datetime.fromisoformat(v)
        if timezone.is_naive(dt):
            dt = timezone.make_aware(dt, timezone.get_current_timezone())
        return dt
    except Exception:
        return None


def user_status_view(request):
    branch_id = request.session.get("last_branch_id") or request.session.get("pending_qr_branch_id")
    branch_name = request.session.get("last_branch_name") or request.session.get("pending_qr_branch_name") or "This Branch"

    # -------------------
    # defaults (old keys)
    # -------------------
    this_branch_total = 0
    this_branch_today = 0
    this_branch_last = None

    today_total_all = 0
    today_unique_branches = 0
    per_branch_today = []

    total_all = 0
    last_visit_anywhere = "—"

    # -------------------
    # NEW: pending + history
    # -------------------
    pending_items = []
    history_days = []

    # ✅ IST day start (local)
    now_ts = timezone.localtime(timezone.now())
    start_of_day = now_ts.replace(hour=0, minute=0, second=0, microsecond=0)

    # ✅ method label map (Admin dropdown labels la)
    method_label_map = {
        "qr_pin": "QR scan + PIN at outlet",
        "qr_code": "QR code",
        "offer_day_pin": "Offer Day PIN",
    }

    if request.user.is_authenticated:
        base_all = UserVisitEvent.objects.filter(user=request.user)
        total_all = base_all.count()

        # ✅ Today across ALL branches
        base_today = base_all.filter(created_at__gte=start_of_day)
        today_total_all = base_today.count()
        today_unique_branches = base_today.values("branch_id").distinct().count()

        # ✅ Per-branch today breakdown
        per_branch_today = list(
            base_today
            .values("branch_id", "branch__name")
            .annotate(today_visits=Count("id"), last_visit=Max("created_at"))
            .order_by("-last_visit")
        )

        # ✅ This branch stats (only if branch_id exists)
        if branch_id:
            qs = base_all.filter(branch_id=branch_id)
            this_branch_total = qs.count()
            this_branch_today = qs.filter(created_at__gte=start_of_day).count()
            last_obj = qs.order_by("-created_at").first()
            this_branch_last = last_obj.created_at if last_obj else None

        # ✅ Global last visit (anywhere)
        last_any = base_all.order_by("-created_at").first()
        if last_any:
            last_visit_anywhere = timezone.localtime(last_any.created_at).strftime("%d %b %Y, %I:%M %p")

        # ✅ HISTORY timeline (day-wise buckets)
        events = (
            base_all
            .select_related("branch")
            .order_by("-created_at")[:120]
        )

        buckets = {}
        for e in events:
            d = timezone.localdate(e.created_at)
            buckets.setdefault(d, []).append(e)

        for d in sorted(buckets.keys(), reverse=True):
            items = []
            for e in buckets[d]:
                method_raw = (e.visit_method or "").strip()
                items.append({
                    "created_at": timezone.localtime(e.created_at),
                    "branch_id": e.branch_id,
                    "branch_name": getattr(e.branch, "name", "Branch"),
                    "desk": e.desk or "",
                    "visit_method": method_raw,  # raw (optional)
                    "visit_method_label": method_label_map.get(method_raw) or (method_raw or "—"),
                    "staff_name": e.staff_name or "",
                    "staff_code": e.staff_code or "",
                    "state": "done",
                })
            history_days.append({
                "date": d,
                "count": len(items),
                "items": items
            })

    # -------------------
    # Pending status (from session)
    # -------------------
    pending_token = (request.session.get("pending_qr_token") or "").strip()
    pending_branch_id = request.session.get("pending_qr_branch_id")
    pending_started_at = request.session.get("pending_qr_started_at")
    pending_desk = request.session.get("pending_qr_desk") or ""
    pending_method = request.session.get("pending_qr_method") or "scan"  # scan|pin

    if pending_token and pending_branch_id:
        b = Branch.objects.filter(id=pending_branch_id).only("id", "name").first()
        started_at_dt = _parse_iso_dt(pending_started_at)

        pending_items.append({
            "token": pending_token,
            "branch_id": pending_branch_id,
            "branch_name": b.name if b else "Branch",
            "desk": pending_desk,
            "method": pending_method,
            "method_label": "QR + PIN" if pending_method == "pin" else "QR Scan",
            "started_at": started_at_dt,
        })

    # -------------------
    # offer visit_unit (old logic)
    # -------------------
    visit_unit = "qr_pin"
    if branch_id:
        offer = (
            ComplementaryOffer.objects
            .filter(kind="complementary_offer", is_active=True)
            .filter(models.Q(all_branches=True) | models.Q(eligible_branches=branch_id))
            .only("visit_unit")
            .first()
        )
        if offer:
            visit_unit = offer.visit_unit

    # -------------------
    # ✅ Dummy offers claimed (for now)
    # -------------------
    offers_claimed_total = 0
    offers_claimed_today = 0
    offers_claimed_label = "Dummy (will connect later)"

    # -------------------
    # ctx (old keys + new keys)
    # -------------------
    ctx = {
        # OLD: This branch
        "branch_name": branch_name,
        "total_visits": this_branch_total,
        "today_visits": this_branch_today,
        "last_visit": timezone.localtime(this_branch_last).strftime("%Y-%m-%d %H:%M") if this_branch_last else "—",
        "visit_unit": visit_unit,
        "total_all": total_all,

        # OLD: All branches today
        "today_total_all": today_total_all,
        "today_unique_branches": today_unique_branches,
        "per_branch_today": per_branch_today,

        # NEW: global + pending + history
        "last_visit_anywhere": last_visit_anywhere,
        "pending_items": pending_items,
        "history_days": history_days,

        # NEW: dummy offers
        "offers_claimed_total": offers_claimed_total,
        "offers_claimed_today": offers_claimed_today,
        "offers_claimed_label": offers_claimed_label,
    }

    return render(request, "user_interface/user_status_view/user_status.html", ctx)
# models


# from .models import BranchGenerateVisitPin, UserVerifyVisitPin, UserVisitEvent


# offers/user_views.py




# models imports (make sure these are present)
# from .models import BranchGenerateVisitPin, UserVisitEvent, UserVerifyVisitPin, QRToken, YashPin


@require_POST
@csrf_protect
@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def user_verify_visit_pin(request):
    """
    USER enters STAFF-GENERATED VISIT PIN (BranchGenerateVisitPin)

    ✅ ONE PLACE tracking:
      1) verify staff visit PIN (BranchGenerateVisitPin)
      2) confirm pending QR (QRToken) which user came from (scan/pin flow)
      3) if qr-pin flow -> also burn YashPin
      4) create UserVisitEvent (ONLY once)
      5) create UserVerifyVisitPin audit row (admin)
      6) mark QRToken.used / used_via / used_by
      7) clear pending session locks
    """

    # -------------------------
    # 0) read input
    # -------------------------
    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        payload = {}

    pin = str(payload.get("pin", "")).strip()
    if not (pin.isdigit() and len(pin) == 4):
        return JsonResponse({"ok": False, "error": "Enter a valid 4-digit PIN."}, status=400)

    now_ts = timezone.now()

    # -------------------------
    # 1) MUST have pending QR context (scan_verify / pin_verify set these)
    # -------------------------
    token = (request.session.get("pending_qr_token") or "").strip()
    if not token:
        return JsonResponse(
            {"ok": False, "error": "No pending QR found. Please scan again."},
            status=400,
        )

    pending_method = request.session.get("pending_qr_method") or "scan"  # "scan" | "pin"
    pending_pin_row_id = request.session.get("pending_pin_row_id")       # only for qr-pin flow

    # ✅ staff visit pin MUST be verified for same branch user came from
    branch_id = request.session.get("pending_qr_branch_id") or request.session.get("last_branch_id")
    if not branch_id:
        return JsonResponse({"ok": False, "error": "Branch context missing. Please scan QR again."}, status=400)

    # -------------------------
    # 2) mark expired visit pins globally (optional)
    # -------------------------
    BranchGenerateVisitPin.objects.filter(
        expired=False,
        expires_at__lte=now_ts,
    ).update(expired=True, expired_at=now_ts)

    # -------------------------
    # 3) find matching BranchGenerateVisitPin row (branch-scoped!)
    # -------------------------
    qs = (
        BranchGenerateVisitPin.objects
        .select_related("branch")
        .filter(branch_id=branch_id, used=False, expired=False, expires_at__gt=now_ts)
        .order_by("-created_at")
    )

    candidates = list(qs[:120])  # small recent window
    matched_visit_pin = None
    for row in candidates:
        if check_password(pin, row.pin_hash):
            matched_visit_pin = row
            break

    if not matched_visit_pin:
        return JsonResponse({"ok": False, "error": "Invalid or expired visit PIN."}, status=400)

    # -------------------------
    # 4) ATOMIC: lock & update everything consistently
    # -------------------------
    with transaction.atomic():
        now_ts = timezone.now()

        # 4A) lock visit pin row
        matched_visit_pin = (
            BranchGenerateVisitPin.objects
            .select_for_update()
            .select_related("branch")
            .get(pk=matched_visit_pin.pk)
        )

        if matched_visit_pin.used:
            return JsonResponse({"ok": False, "error": "PIN already used."}, status=409)

        if matched_visit_pin.expired or matched_visit_pin.expires_at <= now_ts:
            matched_visit_pin.expired = True
            matched_visit_pin.expired_at = now_ts
            matched_visit_pin.save(update_fields=["expired", "expired_at"])
            return JsonResponse({"ok": False, "error": "PIN expired."}, status=410)

        # 4B) lock QR token (pending token)
        qt = (
            QRToken.objects
            .select_for_update()
            .select_related("branch")
            .filter(token=token)
            .first()
        )
        if not qt:
            return JsonResponse({"ok": False, "error": "QR not found. Please scan again."}, status=400)

        if qt.expires_at <= now_ts:
            return JsonResponse({"ok": False, "error": "QR expired. Please scan again."}, status=400)

        if qt.used:
            return JsonResponse({"ok": False, "error": "QR already used. Please generate again."}, status=400)

        # ✅ STRICT: QR branch and VisitPin branch must match
        if int(qt.branch_id) != int(matched_visit_pin.branch_id):
            return JsonResponse(
                {"ok": False, "error": "Branch mismatch. Please scan correct branch QR and try again."},
                status=400,
            )

        # 4C) final one-per-day enforcement (per-branch)
        start_of_day = now_ts.replace(hour=0, minute=0, second=0, microsecond=0)
        already = UserVisitEvent.objects.filter(
            user=request.user,
            branch=qt.branch,
            created_at__gte=start_of_day,
        ).exists()
        if already:
            return JsonResponse({
                "ok": True,
                "already_claimed_today": True,
                "redirect_url": reverse("offers:user_status"),
            })

        # 4D) If user came via qr-pin flow → burn YashPin also
        staff_name = qt.staff_name or ""
        staff_code = qt.staff_code or ""
        desk = qt.desk or ""

        if pending_method == "pin":
            # must have row id
            if not pending_pin_row_id:
                return JsonResponse({"ok": False, "error": "PIN session missing. Please re-enter QR PIN."}, status=400)

            pin_row = (
                YashPin.objects
                .select_for_update()
                .select_related("branch", "qr_token")
                .filter(pk=pending_pin_row_id)
                .first()
            )
            if not pin_row:
                return JsonResponse({"ok": False, "error": "QR PIN session expired. Please re-enter."}, status=400)

            if pin_row.used or pin_row.expires_at <= now_ts:
                return JsonResponse({"ok": False, "error": "QR PIN expired. Please re-enter."}, status=400)

            if pin_row.qr_token_id != qt.id:
                return JsonResponse({"ok": False, "error": "QR PIN mismatch. Please re-enter."}, status=400)

            # burn qr-pin row
            pin_row.used = True
            pin_row.used_at = now_ts
            pin_row.used_by = request.user
            pin_row.save(update_fields=["used", "used_at", "used_by"])

            # prefer staff/desk from qr-pin row (if set)
            staff_name = pin_row.staff_name or staff_name
            staff_code = pin_row.staff_code or staff_code
            desk = pin_row.desk or desk

        # 4E) burn QRToken now
        qt.used = True
        qt.used_at = now_ts
        qt.used_by = request.user
        qt.used_via = "pin" if pending_method == "pin" else "scan"
        qt.save(update_fields=["used", "used_at", "used_by", "used_via"])

        # 4F) burn STAFF visit pin (BranchGenerateVisitPin)
        matched_visit_pin.used = True
        matched_visit_pin.used_at = now_ts
        matched_visit_pin.save(update_fields=["used", "used_at"])

        # choose desk/staff snapshots (prefer VisitPin snapshots if present)
        final_desk = (matched_visit_pin.desk or desk or "")
        final_staff_name = (getattr(matched_visit_pin, "staff_name", "") or "").strip() or staff_name
        final_staff_code = (getattr(matched_visit_pin, "staff_code", "") or "").strip() or staff_code

        # 4G) create audit row (admin table)
        UserVerifyVisitPin.objects.create(
            branch=matched_visit_pin.branch,
            desk=final_desk,
            token=qt.token,                 # ✅ link visit pin audit to QR token
            pin_hash=matched_visit_pin.pin_hash,
            expires_at=matched_visit_pin.expires_at,
            used=True,
            expired=False,
            used_by=request.user if request.user.is_authenticated else None,
            used_at=now_ts,
            staff_name=final_staff_name,
            staff_code=final_staff_code,
        )

        # 4H) create visit event (ONLY ONCE)
        UserVisitEvent.objects.create(
            user=request.user,
            branch=qt.branch,
            token=qt.token,
            desk=final_desk,
            visit_method="qr_pin" if pending_method == "pin" else "qr_screenshot",
            staff_name=final_staff_name,
            staff_code=final_staff_code,
        )

    # -------------------------
    # 5) session update + clear pending locks
    # -------------------------
    request.session["last_branch_id"] = qt.branch_id
    request.session["last_branch_name"] = qt.branch.name
    request.session["last_branch_desk"] = qt.desk or ""
    request.session["last_visit_token"] = qt.token
    request.session["last_qr_ok_at"] = timezone.now().isoformat()

    for k in (
        "pending_qr_token",
        "pending_qr_branch_id",
        "pending_qr_desk",
        "pending_qr_started_at",
        "pending_pin_row_id",
        "pending_qr_method",
    ):
        request.session.pop(k, None)

    return JsonResponse({
        "ok": True,
        "message": "Visit verified successfully ✅",
        "branch_name": qt.branch.name,
        "redirect_url": reverse("offers:user_status"),
    })


