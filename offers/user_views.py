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
    # Branch session active → branch home (login page kanakunda)
    if request.session.get("branch_id"):
        return redirect("offers:branch_home")

    # Already authenticated → route by role (superuser → admin home)
    if request.user.is_authenticated:
        if request.user.is_superuser:
            return redirect("offers:admin_home")
        return redirect("offers:user_home")

    return render(request, "user_registration/user_login.html")


# =========================
# User Home + Name modal flow
# =========================

NAME_RE = re.compile(r"^[^\s].{1,39}$")  # 2–40 chars, Unicode-friendly


@csrf_protect
@login_required
@never_cache
def user_home_page(request):
    # Superusers shouldn’t see user home
    if request.user.is_superuser:
        return redirect("offers:admin_home")

    # Profile
    prof = getattr(request.user, "profile", None)
    if prof is None:
        prof, _ = Profile.objects.get_or_create(user=request.user)

    disp = (prof.display_name or "").strip()
    need_name = (disp == "")

    # Branches for “Branches” card
    LIMIT = 12  # show first 12 as small tiles
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
# QR token helpers (scan / visit count)
# =========================

def decode_base64_url(s: str) -> bytes:
    """Decode a Base64 URL-safe string back into bytes."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def create_token_signature(payload_b64: str) -> str:
    """Create HMAC-SHA256 signature for the given payload using SECRET_KEY."""
    key = (getattr(settings, "OZ_QR_SIGNING_KEY", None) or settings.SECRET_KEY).encode("utf-8")
    mac = hmac.new(key, payload_b64.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")


def verify_qr_token(token: str):
    """Verify QR token signature + expiry, return {bid, desk, exp}."""
    try:
        payload_b64, sig_b64 = token.split(".", 1)
    except ValueError:
        raise ValueError("Bad token format")

    good_sig = create_token_signature(payload_b64)
    if not hmac.compare_digest(good_sig, sig_b64):
        raise ValueError("Bad signature")

    doc = json.loads(decode_base64_url(payload_b64))
    if int(doc.get("exp", 0)) < int(time.time()):
        raise ValueError("Expired")

    bid = int(doc.get("bid"))
    desk = str(doc.get("desk") or "A1")[:12]
    return {"bid": bid, "desk": desk, "exp": int(doc["exp"])}


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
QR_TTL_SECS = 180  # same as in qr_generation


def verify_legacy_colon_token(token: str):
    """Decode Django TimestampSigner token: payload:timestamp:signature."""
    try:
        data = signing.loads(token, salt=SIGN_SALT, max_age=QR_TTL_SECS + 30)
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
    """
    POST /qrg/pin-verify/
    { "pin": "1234" }  →  { ok:true, next:"/visit-count/?token=..." }
    """
    print(">>> PIN_VERIFY VIEW HIT")  # debug optional

    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        data = {}

    raw_pin = str(data.get("pin") or "").strip()
    # keep only digits, max 4
    pin = re.sub(r"\D", "", raw_pin)[:PIN_LEN]

    # 4-digit validation
    if not re.fullmatch(r"\d{4}", pin):
        return JsonResponse({"ok": False, "error": "Enter a valid 4-digit PIN."}, status=400)

    now_ts = timezone.now()

    # Live candidates: not expired, not used (limit few rows)
    qs = (
        QRPin.objects
        .filter(expires_at__gte=now_ts, used=False)
        .order_by("-created_at")
    )

    row = None
    for cand in qs[:20]:  # safety limit
        if verify_qr_pin(cand, pin):   # 👈 uses qr_pin_service logic
            row = cand
            break

    if row is None:
        return JsonResponse({"ok": False, "error": "Invalid or expired PIN."}, status=400)

    if row.expires_at < now_ts:
        return JsonResponse({"ok": False, "error": "PIN expired."}, status=400)

    if getattr(row, "used", False):
        return JsonResponse({"ok": False, "error": "PIN already used."}, status=400)

    # ✅ success → mark used & redirect
    if hasattr(row, "used"):
        row.used = True
        row.save(update_fields=["used"])

    next_url = reverse("offers:user_visit_count")
    next_url = f"{next_url}?token={row.token}"

    return JsonResponse({"ok": True, "next": next_url})


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
# Visit count page
# =========================

@cache_control(no_store=True, no_cache=True, must_revalidate=True)
@never_cache
def user_visit_count_view(request):
    token = request.GET.get("token")

    branch = None
    visit_unit = "qr_screenshot"   # default if not found

    if token:
        try:
            if "." in token:
                info = verify_qr_token(token)
            elif ":" in token:
                info = verify_legacy_colon_token(token)
            else:
                raise ValueError("Bad token format")

            branch = Branch.objects.filter(pk=info["bid"]).only("id", "name").first()
            if not branch:
                raise ValueError("Branch not found")

            desk = info.get("desk")

            # Save in session
            request.session["last_branch_id"] = branch.id
            request.session["last_branch_name"] = branch.name

            if desk:
                request.session["last_branch_desk"] = str(desk)
            else:
                request.session.pop("last_branch_desk", None)

            request.session["last_qr_ok_at"] = timezone.now().isoformat()

        except ValueError:
            return redirect("offers:user_home")

    # ================================
    # Fetch visit_unit from active offer
    # ================================
    branch_id = request.session.get("last_branch_id")
    if branch_id:
        # Active complementary_offer for this branch
        offer = (
            ComplementaryOffer.objects
            .filter(kind="complementary_offer", is_active=True)
            .filter(models.Q(all_branches=True) | models.Q(eligible_branches=branch_id))
            .only("visit_unit")
            .first()
        )
        if offer:
            visit_unit = offer.visit_unit  # qr_pin or qr_screenshot

    # ================================
    # Build context for template
    # Replace TODO visits later
    # ================================
    ctx = {
        "branch_name": request.session.get("last_branch_name", "Unknown Branch"),
        "total_visits": 12,
        "today_visits": 1,
        "last_visit": "2025-11-09 18:45",
        "visit_unit": visit_unit,              # 👈 VERY IMPORTANT
        "token": token,                        # optional, needed for upload later
    }

    return render(
        request,
        "user_interface/user_visit_count/user_visit_count_modal.html",
        ctx,
    )
