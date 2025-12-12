# In future, switch to encrypted identifier (email/phone) + hash for lookup

# offers/user_views.py

from datetime import timedelta
from decimal import Decimal, InvalidOperation
import base64
import hashlib
import hmac
import json
import re
import time
import urllib.parse

from django.conf import settings
from django.contrib.auth import get_user_model, login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.core import signing
from django.core.mail import send_mail
from django.db.models.functions import Lower
from django.http import JsonResponse, HttpResponseBadRequest
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache, cache_control
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST
from django.db import models  # Q kosam
from .models import LoginVisit
from django.utils import timezone
from offers.models import UserVisitEvent   # 👈 add this import



from .models import (
    Profile,
    Branch,
    LoginOTP,
    UserLocationPing,
    QRPin,
    ComplementaryOffer,
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
from .qr_pin_service import verify_qr_pin


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




@csrf_protect
@login_required
@never_cache
def user_home_page(request):
    # Superusers shouldn’t see user home
    if request.user.is_superuser:
        return redirect("offers:admin_home")

    client_ip = get_client_ip(request)
    ua = request.META.get("HTTP_USER_AGENT", "")

    today = timezone.localdate()

    LoginVisit.objects.update_or_create(
        user=request.user,
        visit_date=today,
        defaults={
            "source": "login",
            "ip_address": client_ip,
            "user_agent": ua,
        },
    )

    # 👇 ONE-PER-DAY VISIT FLAG (qr_screenshot + qr_pin rendu cover)
    now_ts = timezone.now()
    start_of_day = now_ts.replace(hour=0, minute=0, second=0, microsecond=0)

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
    branches = list(all_branches_qs[:LIMIT])

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
            # 🔥 ADD THIS
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

PIN_LEN = 4  # 4-digit PIN for QR


@require_POST
@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def pin_verify(request):

    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        data = {}

    raw_pin = str(data.get("pin") or "").strip()
    pin = re.sub(r"\D", "", raw_pin)[:PIN_LEN]

    if not re.fullmatch(r"\d{4}", pin):
        return JsonResponse({"ok": False, "error": "Enter a valid 4-digit PIN."}, status=400)

    now_ts = timezone.now()

    qs = (
        QRPin.objects
        .filter(expires_at__gte=now_ts, used=False)
        .order_by("-created_at")
    )

    row = None
    for cand in qs[:20]:
        if verify_qr_pin(cand, pin):
            row = cand
            break

    if row is None:
        return JsonResponse({"ok": False, "error": "Invalid or expired PIN."}, status=400)

    if row.expires_at < now_ts:
        return JsonResponse({"ok": False, "error": "PIN expired."}, status=400)

    if getattr(row, "used", False):
        return JsonResponse({"ok": False, "error": "PIN already used."}, status=400)

    # Mark pin used
    row.used = True
    row.save(update_fields=["used"])

    # ===========================================================
    # 🔥 ONE-PER-DAY CHECK (user + branch)
    # ===========================================================
    already_claimed_today = False
    user = request.user if request.user.is_authenticated else None

    if user:
        now = timezone.now()
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)

        already_claimed_today = UserVisitEvent.objects.filter(
            user=user,
            branch=row.branch,
            created_at__gte=start_of_day,
        ).exists()

        # Create visit event only if first time today
        if not already_claimed_today:
            UserVisitEvent.objects.create(
                user=user,
                branch=row.branch,
                token=row.token,
                desk=row.desk,
                visit_method="qr_pin",
                staff_name=row.staff_name,
                staff_code=row.staff_code,
            )

    next_url = reverse("offers:user_visit_intake") + f"?token={row.token}"


    return JsonResponse({
        "ok": True,
        "next": next_url,
        "already_claimed_today": already_claimed_today,   # 👈 Frontend popup uses this
    })


# offers/user_views.py (for example)




from offers.qr_token_utils import parse_qr_token as verify_qr_token


import logging
logger = logging.getLogger(__name__)


@require_POST
@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def scan_verify(request):
    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        data = {}

    raw_input = str(data.get("token") or "").strip()
    if not raw_input:
        return JsonResponse({"ok": False, "error": "No token provided."}, status=400)

    # 👇 URL or raw token rendu handle
    token = extract_qr_token_from_raw(raw_input)
    if not token:
        return JsonResponse({"ok": False, "error": "Invalid QR token format."}, status=400)

    try:
        parsed = verify_qr_token(token, mark_used=True)
    except ValueError as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=400)

    branch_id = parsed["bid"]
    desk = parsed.get("desk")
    now_ts = timezone.now()

    # IMPORTANT: use the canonical `token` for DB lookup, not raw_input
    row = QRPin.objects.filter(token=token).first()
    if row is not None:
        if row.expires_at < now_ts:
            return JsonResponse({"ok": False, "error": "PIN expired."}, status=400)

        if getattr(row, "used", False):
            return JsonResponse({"ok": False, "error": "Already used"}, status=400)

        row.used = True
        row.used_at = now_ts
        row.save(update_fields=["used", "used_at"])

    # ONE-PER-DAY: user + branch
    already_claimed_today = False
    user = request.user if request.user.is_authenticated else None

    if user:
        now = timezone.now()
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)

        already_claimed_today = UserVisitEvent.objects.filter(
            user=user,
            branch_id=branch_id,
            created_at__gte=start_of_day,
        ).exists()

        if not already_claimed_today:
            event_kwargs = {
                "user": user,
                "branch_id": branch_id,
                "token": token,
                "desk": desk,
                "visit_method": "qr_screenshot",
            }
            # QRPin row dakkite staff snapshot kuda store cheddam
            if row is not None:
                event_kwargs["staff_name"] = getattr(row, "staff_name", "") or ""
                event_kwargs["staff_code"] = getattr(row, "staff_code", "") or ""

            UserVisitEvent.objects.create(**event_kwargs)

    next_url = reverse("offers:user_visit_intake") + f"?token={token}"


    return JsonResponse({
        "ok": True,
        "next": next_url,
        "already_claimed_today": already_claimed_today,
    })





# ============================================
# branch offers  view in user interface
# =============================================

def branch_offers_in_userinterface(request, branch_id):
    branch = get_object_or_404(Branch, id=branch_id)
    now = timezone.now()

    base_qs = (
        ComplementaryOffer.objects
        .filter(
            is_active=True,
            start_at__lte=now,
        )
        .filter(
            models.Q(all_branches=True) |
            models.Q(eligible_branches=branch)
        )
        .distinct()
    )

    offers = base_qs.order_by("id")

    # 👇 Complementary offer special row (calendar lo use cheyyadaniki)
    free_plate_offer = base_qs.filter(kind="complementary_offer").order_by("id").first()

    context = {
        "branch": branch,
        "offers": offers,
        "active_offer_count": offers.count(),
        "is_open_now": True,
        "free_plate_offer": free_plate_offer,   # 🔥 still same context key
    }
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
def user_visit_intake_view(request):
    """
    QR / PIN verify taruvata first hit oka sari ikkade ki vastundi.

    Task:
    - ?token= ni verify cheyyadam
    - Branch ni find cheyyadam
    - Session lo last_branch_* context store cheyyadam
    - Clean status page (/visit-count/) ki redirect cheyyadam
    """
    token = request.GET.get("token")
    if not token:
        # token lekunda direct hit aithe, straight ga status page ki velipoddam
        return redirect("offers:user_visit_count")

    try:
        if "." in token:
            # new style JWT-like token
            info = verify_qr_token(token, allow_used=True)
        elif ":" in token:
            # legacy colon token
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

        # Session lo visit context store
        request.session["last_branch_id"] = branch.id
        request.session["last_branch_name"] = branch.name
        request.session["last_qr_ok_at"] = timezone.now().isoformat()

        if desk:
            request.session["last_branch_desk"] = str(desk)
        else:
            request.session.pop("last_branch_desk", None)

        # (optional) debug kosam token cache
        request.session["last_visit_token"] = token

        # IMPORTANT:
        # UserVisitEvent already scan_verify / pin_verify lo create ayyindi,
        # ikkada malli create cheyyakunda clean status URL ki redirect.
        return redirect("offers:user_visit_count")

    except ValueError:
        # bad / expired / invalid token → home
        return redirect("offers:user_home")






@cache_control(no_store=True, no_cache=True, must_revalidate=True)
@never_cache
def user_visit_count_view(request):
    """
    Status / visits page:
    - Header lo 'Status' click → ikkade
    - Scan / PIN taruvata intake → ikkade
    """
    visit_unit = "qr_screenshot"   # default

    # ================================
    # 1) Session lo branch_id required
    # ================================
    branch_id = request.session.get("last_branch_id")
    if not branch_id:
        # direct /visit-count/ open chesina or session lost → back to home
        return redirect("offers:user_home")

    # -------------------------------
    # Fetch visit_unit from active offer
    # -------------------------------
    offer = (
        ComplementaryOffer.objects
        .filter(kind="complementary_offer", is_active=True)
        .filter(
            models.Q(all_branches=True) |
            models.Q(eligible_branches=branch_id)
        )
        .only("visit_unit")
        .first()
    )
    if offer:
        visit_unit = offer.visit_unit

    # -------------------------------
    # Fetch visit stats from DB
    # -------------------------------
    qs = UserVisitEvent.objects.filter(branch_id=branch_id)

    if request.user.is_authenticated:
        qs = qs.filter(user=request.user)

    total_visits = qs.count()

    start_of_day = timezone.now().replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    today_visits = qs.filter(created_at__gte=start_of_day).count()

    last_obj = qs.order_by("-created_at").first()
    last_visit = last_obj.created_at if last_obj else None

    # -------------------------------
    # Build context
    # -------------------------------
    ctx = {
        "branch_name": request.session.get("last_branch_name", "Unknown Branch"),
        "total_visits": total_visits,
        "today_visits": today_visits,
        "last_visit": (
            last_visit.strftime("%Y-%m-%d %H:%M") if last_visit else None
        ),
        "visit_unit": visit_unit,
        # template ki token kavalsina avasaram ledu, but debug kosam isthe:
        "token": request.session.get("last_visit_token"),
    }

    return render(
        request,
        "user_interface/user_visit_count/user_visit_count_modal.html",
        ctx,
    )



from django.shortcuts import render, redirect

def user_status_view(request):
    # (Optional) auth required anukunte uncomment
    # if not request.user.is_authenticated:
    #     return redirect("offers:user_login")

    return render(
        request,
        "user_interface/user_status_view/user_status.html"
    )


