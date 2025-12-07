# offers/admin_views.py
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache

from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse, HttpResponseBadRequest
from django.db import transaction
from django.views.decorators.http import require_GET, require_POST
from zoneinfo import ZoneInfo
from datetime import datetime
import json
import re

from django.core.validators import validate_email
from django.core.exceptions import ValidationError

from .models import ComplementaryOffer, Branch
from .qr_pin_service import generate_qr_token_and_pin  # (still here if you uncomment API later)

# ---- helpers -------------------------------------------------

def _is_superuser(user):
    return user.is_authenticated and user.is_superuser


def _safe_next(request, candidate, default):
    if candidate and url_has_allowed_host_and_scheme(
        url=candidate, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return candidate
    return default


IST = ZoneInfo("Asia/Kolkata")


def _b(val: str) -> bool:
    if val is None:
        return False
    return str(val).lower() in ("on", "true", "1", "yes")


def _parse_dt_local(s: str):
    if not s:
        return None
    dt = datetime.strptime(s, "%Y-%m-%dT%H:%M")
    return dt.replace(tzinfo=IST)



@never_cache
def admin_login_view(request):
    if request.user.is_authenticated:
        dest = reverse("offers:admin_home") if request.user.is_superuser else reverse("offers:user_home")
        raw_next = request.GET.get("next")
        if request.user.is_superuser:
            dest = _safe_next(request, raw_next, dest)
        else:
            dest = _safe_next(
                request,
                raw_next if (raw_next and not raw_next.startswith("/admin")) else None,
                dest,
            )
        return redirect(dest)

    if request.method == "POST":
        username = (request.POST.get("username") or "").strip()
        password = request.POST.get("password") or ""
        user = authenticate(request, username=username, password=password)
        if user:
            if not user.is_superuser:
                messages.error(request, "You are not a superuser.")
                return render(request, "admin_registration/admin_login.html")
            login(request, user)
            default = reverse("offers:admin_home")
            raw_next = request.POST.get("next") or request.GET.get("next")
            return redirect(_safe_next(request, raw_next, default))
        messages.error(request, "Invalid username or password.")
    return render(request, "admin_registration/admin_login.html")


def admin_logout_view(request):
    logout(request)
    return redirect("offers:admin_login")

# ---- helpers: safe positive int parser -----------------------


def parse_positive_int(val, default=None, min_value=None):
    """
    Safe positive integer parser:
    - empty / invalid -> default
    - optional min_value clamp
    """
    if val is None:
        return default
    try:
        n = int(str(val).strip())
    except (TypeError, ValueError):
        return default
    if min_value is not None and n < min_value:
        return default if default is not None else min_value
    return n





from django.contrib.auth.decorators import login_required, user_passes_test
from django.utils import timezone
from django.db.models.functions import Lower

from .models import Branch, LoginVisit


def _is_superuser(user):
    return user.is_superuser


@login_required(login_url="offers:admin_login")
@user_passes_test(_is_superuser, login_url="offers:admin_login")
@never_cache
def admin_home(request):
    """
    Admin dashboard: branch-level summary.

    Shows:
      - total_branches        → system lo enni branches register ayyayo
      - branches_active_today → ee roju login ayina branches count
      - branches (first 12)   → UI lo cards/pills kosam
    """

    # 1) Total branches
    total_branches = Branch.objects.count()

    # 2) Branch list (first 12, name order)
    LIMIT = 12
    all_branches_qs = Branch.objects.order_by(Lower("name"))
    branches = list(all_branches_qs[:LIMIT])

    # 3) Today date (IST / project timezone)
    today = timezone.localdate()

    # 4) Today login visits (LoginVisit lo per-user, per-day row untundi)
    login_qs = (
        LoginVisit.objects
        .filter(visit_date=today)
        .select_related("user")
    )

    # 5) Aa users emails collect cheddam
    #    assumption: Branch.email == User.email (branch login mail)
    emails = {
        lv.user.email
        for lv in login_qs
        if getattr(lv.user, "email", None)
    }

    # 6) A emails ki match ayye branches = today active branches
    branches_active_today = (
        Branch.objects
        .filter(email__in=emails)
        .distinct()
        .count()
    )

    ctx = {
        "branches": branches,
        "total_branches": total_branches,
        "branches_active_today": branches_active_today,
    }
    return render(request, "homepage/home.html", ctx)


@login_required(login_url="offers:admin_login")
@user_passes_test(_is_superuser, login_url="offers:admin_login")
@never_cache
def branch_detail_view(request, branch_id):
    """Single branch detail page (admin panel)."""
    try:
        branch = Branch.objects.get(id=branch_id)
    except Branch.DoesNotExist:
        return redirect("offers:admin_home")

    ctx = {
        "branch": branch,
        "created_at": branch.created_at,
        "email": branch.email,
    }

    return render(request, "homepage/branchdata_in_adminpanel.html", ctx)





# ---- save complementary offer (exclude_staff, branches, extra_nths) ---------


@login_required(login_url="offers:admin_login")
@user_passes_test(_is_superuser, login_url="offers:admin_login")
def complementary_offer_save(request):
    if request.method != "POST":
        return HttpResponseBadRequest("POST required")

    p = request.POST
    try:
        FIXED_ISSUANCE_MODE  = "auto"
        FIXED_REDEEM_METHODS = "qr"
        FIXED_FALLBACK_LEN   = 6

        # ---------- Nth + numbers ----------
        # nth optional: empty -> None
        nth_val = parse_positive_int(p.get("nth"), default=None, min_value=1)

        dedupe_value       = parse_positive_int(p.get("dedupe_value"),       default=1,  min_value=1)
        claim_expiry_hours = parse_positive_int(p.get("claim_expiry_hours"), default=24, min_value=1)
        total_cap          = parse_positive_int(p.get("total_cap"),          default=0,  min_value=0)
        daily_cap          = parse_positive_int(p.get("daily_cap"),          default=0,  min_value=0)

        # ---------- extra milestones (each optional) ----------
        raw_extra  = p.getlist("extra_nths[]")
        extra_nths = []
        for item in raw_extra:
            item = (item or "").strip()
            if not item:
                continue
            n = parse_positive_int(item, default=None, min_value=1)
            if n is not None:
                extra_nths.append(n)

        # uniq + sorted; can be empty list, that’s fine
        extra_nths = sorted(set(extra_nths))

        # ---------- create offer ----------
        offer_kwargs = dict(
            kind="complementary_offer",
            title="Complementary Offer",
            count_start=p.get("count_start", "user_registration"),
            backfill=_b(p.get("backfill")),
            nth=nth_val,                      # may be None
            repeat=_b(p.get("repeat")),
            visit_unit=p.get("visit_unit", "qr_screenshot"),
            dedupe_value=dedupe_value,
            dedupe_unit=p.get("dedupe_unit", "day"),
            per_user_limit=p.get("per_user_limit", "per_multiple"),
            claim_expiry_hours=claim_expiry_hours,
            total_cap=total_cap,
            daily_cap=daily_cap,
            start_at=_parse_dt_local(p.get("start_at")),
            end_at=_parse_dt_local(p.get("end_at")) if p.get("end_at") else None,
            active_from=p.get("active_from") or None,
            active_to=p.get("active_to") or None,
            issuance_mode=FIXED_ISSUANCE_MODE,
            redeem_type="code",
            redeem_methods=FIXED_REDEEM_METHODS,
            fallback_code_length=FIXED_FALLBACK_LEN,
            segment=p.get("segment", "all"),
            exclude_admin=_b(p.get("exclude_admin")),
        )

        if hasattr(ComplementaryOffer, "extra_nths"):
            offer_kwargs["extra_nths"] = extra_nths   # [] or [..]

        offer = ComplementaryOffer(**offer_kwargs)

        if offer.segment == "custom":
            offer.allow_key  = (p.get("allow_key") or "phone").strip()
            offer.allow_list = (p.get("allow_users") or "").strip()

        # --- time fields ---
        if isinstance(offer.active_from, str) and offer.active_from:
            offer.active_from = datetime.strptime(offer.active_from, "%H:%M").time()
        if isinstance(offer.active_to, str) and offer.active_to:
            offer.active_to = datetime.strptime(offer.active_to, "%H:%M").time()

        # --- branches ---
        all_branches_val = (p.get("all_branches") or "").lower()
        offer.all_branches = all_branches_val in ("on", "true", "1")

        try:
            raw_ids    = p.get("branch_ids") or "[]"
            parsed     = json.loads(raw_ids)
            branch_ids = [int(x) for x in parsed]
            branch_ids = list(dict.fromkeys(branch_ids))[:200]
        except Exception:
            branch_ids = []

        with transaction.atomic():
            offer.full_clean()
            offer.save()

            if offer.all_branches:
                offer.eligible_branches.clear()
            else:
                if branch_ids:
                    qs = Branch.objects.filter(id__in=branch_ids)
                    offer.eligible_branches.set(qs)
                else:
                    offer.eligible_branches.clear()

        return JsonResponse({"ok": True, "id": offer.id, "message": "Offer saved"})

    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=400)

# ---- branches APIs (superuser only) --------------------------


_name_re = re.compile(r"^[a-z0-9]+$")


def _sanitize_name(raw: str) -> str:
    # lowercase, remove spaces, drop non a-z0-9
    s = (raw or "").strip().lower()
    s = s.replace(" ", "")
    s = re.sub(r"[^a-z0-9]", "", s)
    return s


@require_POST
@login_required(login_url="offers:admin_login")
@user_passes_test(_is_superuser, login_url="offers:admin_login")
def branches_create(request):
    # Expect JSON: { "name": "...", "email"?: "...", "latitude"?: float, "longitude"?: float }
    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return JsonResponse({"ok": False, "error": "Invalid JSON body"}, status=400)

    input_name = (payload.get("name") or "").strip()
    email      = (payload.get("email") or "").strip() or None
    latitude   = payload.get("latitude", None)
    longitude  = payload.get("longitude", None)

    if not input_name:
        return JsonResponse({"ok": False, "error": "Name required"}, status=400)

    # normalize and validate
    name = _sanitize_name(input_name)
    if not name:
        return JsonResponse(
            {"ok": False, "error": "Use only lowercase letters and numbers (no spaces)."},
            status=400,
        )
    if len(name) > 120:
        return JsonResponse({"ok": False, "error": "Name too long (max 120)."}, status=400)
    if not _name_re.fullmatch(name):
        return JsonResponse(
            {"ok": False, "error": "Only a–z and 0–9 allowed (no spaces/specials)."},
            status=400,
        )

    # optional email validation
    if email:
        try:
            validate_email(email)
        except ValidationError:
            return JsonResponse({"ok": False, "error": "Invalid email"}, status=400)

    # optional coord parsing
    def _parse_coord(val, lo, hi, label):
        if val is None or str(val) == "":
            return None
        try:
            v = float(val)
        except Exception:
            raise ValidationError(f"{label} must be a number")
        if v < lo or v > hi:
            raise ValidationError(f"{label} out of range ({lo}..{hi})")
        return round(v, 6)

    try:
        lat_parsed = _parse_coord(latitude,  -90,  90,  "Latitude")
        lon_parsed = _parse_coord(longitude, -180, 180, "Longitude")
        # if one is given, require both (optional; remove if you want single allowed)
        if (lat_parsed is None) ^ (lon_parsed is None):
            raise ValidationError("Provide both latitude and longitude, or leave both empty")
    except ValidationError as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=400)

    # create or fetch by normalized name
    obj, created = Branch.objects.get_or_create(name=name)

    dirty = []
    if email is not None and getattr(obj, "email", None) != email:
        obj.email = email
        dirty.append("email")
    if lat_parsed is not None and getattr(obj, "latitude", None) != lat_parsed:
        obj.latitude = lat_parsed
        dirty.append("latitude")
    if lon_parsed is not None and getattr(obj, "longitude", None) != lon_parsed:
        obj.longitude = lon_parsed
        dirty.append("longitude")

    if dirty:
        obj.save(update_fields=dirty)

    normalized = (input_name != name)
    return JsonResponse(
        {
            "ok": True,
            "id": obj.id,
            "name": obj.name,
            "email": getattr(obj, "email", "") or "",
            "latitude": getattr(obj, "latitude", None),
            "longitude": getattr(obj, "longitude", None),
            "created": created,
            "normalized": normalized,
            "display_hint": "name lowercased and cleaned" if normalized else "",
        },
        status=(201 if created else 200),
    )


@require_GET
@login_required(login_url="offers:admin_login")
@user_passes_test(_is_superuser, login_url="offers:admin_login")
def branches_search(request):
    q = (request.GET.get("q") or "").strip()
    qs = Branch.objects.all()
    if q:
        qs = qs.filter(name__icontains=q)
    data = [{"id": b.id, "name": b.name} for b in qs.order_by("name")[:20]]
    return JsonResponse(data, safe=False)


