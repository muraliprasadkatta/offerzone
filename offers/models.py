# offers/models.py

from decimal import Decimal, ROUND_HALF_UP
import secrets

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.validators import (
    MinValueValidator,
    MaxValueValidator,
    RegexValidator,
)
from django.db import models
from django.db.models.functions import Lower
from django.utils import timezone

class QRToken(models.Model):
    """
    ✅ Single source of truth for a QR token.
    QR scan OR PIN verify — whichever happens first will mark this token as used.
    """

    USED_VIA_CHOICES = (
        ("", "Unknown"),
        ("scan", "QR Scan"),
        ("pin", "PIN Verify"),
    )

    branch = models.ForeignKey(
        "offers.Branch",
        on_delete=models.CASCADE,
        related_name="qr_tokens",
    )
    desk = models.CharField(max_length=12, blank=True, default="")

    # token string (same token used in /qrg/redeem/<token>)
    token = models.CharField(max_length=200, unique=True, db_index=True)

    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)

    # ✅ unified usage status (scan/pin both affect this)
    used = models.BooleanField(default=False, db_index=True)
    used_at = models.DateTimeField(null=True, blank=True)

    used_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="used_qr_tokens",
    )

    used_via = models.CharField(
        max_length=16,
        choices=USED_VIA_CHOICES,
        blank=True,
        default="",
        db_index=True,
    )

    # ⭐ snapshots (who issued the QR at branch side)
    staff_name = models.CharField(max_length=255, blank=True, default="")
    staff_code = models.CharField(max_length=100, blank=True, default="")

    # optional audit helpers (nice to have)
    last_error = models.CharField(max_length=120, blank=True, default="")
    last_seen_at = models.DateTimeField(null=True, blank=True)  # whenever token was attempted

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["branch", "created_at"]),
            models.Index(fields=["branch", "expires_at", "used"]),
            models.Index(fields=["token", "expires_at"]),
        ]

    def is_expired(self, now=None) -> bool:
        now = now or timezone.now()
        return self.expires_at < now

    def mark_used(self, user=None, via="scan", now=None):
        """
        Call this when you ACCEPT the scan/pin as valid.
        (View lo transaction + select_for_update tho call chestham later.)
        """
        now = now or timezone.now()
        self.used = True
        self.used_at = now
        self.used_by = user
        self.used_via = via or ""
        self.save(update_fields=["used", "used_at", "used_by", "used_via"])

    def __str__(self):
        return f"QRToken({self.branch_id}, used={self.used}, token={self.token[:8]}...)"


class YashPin(models.Model):
    """
    ✅ PIN record linked to one QRToken.
    PIN verify success => mark this used + also mark QRToken used.
    """

    branch = models.ForeignKey(
        "offers.Branch",
        on_delete=models.CASCADE,
        related_name="yash_pins",
    )
    desk = models.CharField(max_length=12, blank=True, default="")

    # 1 PIN belongs to 1 token (simple + no confusion)
    qr_token = models.OneToOneField(
        "offers.QRToken",
        on_delete=models.CASCADE,
        related_name="yash_pin",
    )

    # store only hash (no raw pin)
    pin_hash = models.CharField(max_length=128, db_index=True)

    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)

    used = models.BooleanField(default=False, db_index=True)
    used_at = models.DateTimeField(null=True, blank=True)

    used_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="used_yash_pins",
    )

    # brute-force / audit
    attempts = models.PositiveSmallIntegerField(default=0)
    last_attempt_at = models.DateTimeField(null=True, blank=True)

    # ⭐ staff snapshot (same as QRToken usually, but keep for safety)
    staff_name = models.CharField(max_length=255, blank=True, default="")
    staff_code = models.CharField(max_length=100, blank=True, default="")

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["branch", "created_at"]),
            models.Index(fields=["expires_at", "used"]),
            models.Index(fields=["pin_hash", "expires_at"]),
        ]

    def is_expired(self, now=None) -> bool:
        now = now or timezone.now()
        return self.expires_at < now

    def mark_used(self, user=None, now=None):
        now = now or timezone.now()
        self.used = True
        self.used_at = now
        self.used_by = user
        self.save(update_fields=["used", "used_at", "used_by"])

    def __str__(self):
        return f"YashPin({self.branch_id}, used={self.used}, token={self.qr_token_id})"



User = get_user_model()

class LoginVisit(models.Model):
    """
    Per-day login stamp (IST day). De-dupe = unique(user, visit_date).
    """
    SOURCE_CHOICES = [
        ("login", "Login"),         # future-proof: you can add 'qr', 'self_code' if needed
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="login_visits")
    visit_date = models.DateField()                   # IST calendar date
    source = models.CharField(max_length=16, choices=SOURCE_CHOICES, default="login")
    created_at = models.DateTimeField(auto_now_add=True)

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, default="")

    class Meta:
        unique_together = (("user", "visit_date"),)   # ✅ 1/day de-dupe
        indexes = [
            models.Index(fields=["user", "visit_date"]),
        ]

    def __str__(self):
        return f"{self.user_id}@{self.visit_date} ({self.source})"





# Crockford-like alphabet: easy to read, confuse ayyye chars lekunda
_BRANCH_PID_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

def make_branch_pid(length: int = 10) -> str:
    # 10 chars → 32^10 space (huge). Callable default DB-safe enough for us.
    return ''.join(secrets.choice(_BRANCH_PID_ALPHABET) for _ in range(length))



# allow only lowercase letters and digits
branch_name_validator = RegexValidator(
    regex=r'^[a-z0-9]+$',
    message="Use only lowercase letters and numbers (no spaces or special characters).",
)



# ee imports already untaayi ani assume chestunna:
# from .validators import branch_name_validator
# from .utils import make_branch_pid
# from .models import LoginVisit


class Branch(models.Model):
    name = models.CharField(
        max_length=120,
        unique=True,
        validators=[branch_name_validator],
        help_text="lowercase a–z and 0–9 only; no spaces",
    )
    email = models.EmailField(blank=True, null=True, db_index=True)

    # ✅ Stable public unique id for QR/links
    public_id = models.CharField(
        max_length=12,
        unique=True,              # enforce uniqueness
        default=make_branch_pid,  # auto-generate for new rows
        editable=False,
        db_index=True,
        help_text="Stable public identifier for URLs/QR (immutable).",
    )

    # ✅ manual coords (no auto-geo)
    latitude = models.DecimalField(
        max_digits=9,
        decimal_places=6,
        null=True,
        blank=True,
        validators=[
            MinValueValidator(Decimal("-90")),
            MaxValueValidator(Decimal("90")),
        ],
        help_text="decimal degrees (−90..90) — 6 d.p.",
    )
    longitude = models.DecimalField(
        max_digits=9,
        decimal_places=6,
        null=True,
        blank=True,
        validators=[
            MinValueValidator(Decimal("-180")),
            MaxValueValidator(Decimal("180")),
        ],
        help_text="decimal degrees (−180..180) — 6 d.p.",
    )

    created_at = models.DateTimeField(auto_now_add=True)

    qr_visit_count = models.PositiveIntegerField(default=0)

    # ------- helper methods for today login --------
    def _today_login_qs(self):
        """
        Helper: Ee branch ki, present-day LoginVisit rows filter chestundi.
        Assumption: Branch.email == User.email (branch login email).
        """
        today = timezone.localdate()
        if not self.email:
            return LoginVisit.objects.none()

        return (
            LoginVisit.objects
            .filter(visit_date=today, user__email=self.email)
            .order_by("created_at")
        )

    @property
    def today_first_login(self):
        qs = self._today_login_qs()
        first = qs.first()
        return first.created_at if first else None

    @property
    def today_last_login(self):
        qs = self._today_login_qs()
        last = qs.last()
        return last.created_at if last else None

    class Meta:
        constraints = [
            models.UniqueConstraint(
                Lower("name"),
                name="uniq_branch_name_lower",
            ),
        ]
        indexes = [
            models.Index(
                Lower("name"),
                name="idx_branch_name_lower",
            ),
            models.Index(
                fields=["latitude", "longitude"],
                name="idx_branch_lat_lon",
            ),
            # public_id ki separate db_index already undi; malli index add avasaram ledu
        ]

    def clean(self):
        """Normalize name and enforce coord pair + rounding."""
        # --- name normalize + regex ---
        if self.name:
            raw = self.name.strip()
            norm = "".join(ch for ch in raw.lower() if ch.isalnum())
            if not norm:
                # branch_name_validator lo message use chestunnam
                raise ValidationError({"name": branch_name_validator.message})
            self.name = norm
            branch_name_validator(self.name)

        # --- coord pair rule (both or none) ---
        lat = self.latitude
        lon = self.longitude
        if (lat is None) ^ (lon is None):
            raise ValidationError(
                "Provide both latitude and longitude, or leave both empty"
            )

        # --- round to 6 dp consistently ---
        def r6(v: Decimal) -> Decimal:
            return v.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)

        if lat is not None:
            self.latitude = r6(Decimal(self.latitude))
        if lon is not None:
            self.longitude = r6(Decimal(self.longitude))

    def save(self, *args, **kwargs):
        """
        Ensure normalization + rounding even if clean() not called.
        clean() lo unna logic ki sync lo pettaam.
        """
        # --- name normalize ---
        if self.name:
            self.name = "".join(
                ch for ch in self.name.strip().lower() if ch.isalnum()
            )

        # --- coords rounding (ALWAYS round if present) ---
        def r6(v: Decimal) -> Decimal:
            return v.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)

        if self.latitude is not None:
            self.latitude = r6(Decimal(self.latitude))
        if self.longitude is not None:
            self.longitude = r6(Decimal(self.longitude))

        super().save(*args, **kwargs)

    def __str__(self):
        return self.name

    @property
    def coords(self):
        """
        Return (lat, lon) as float tuple if both set; else None.
        """
        if self.latitude is not None and self.longitude is not None:
            return float(self.latitude), float(self.longitude)
        return None





# offers/models.py
from django.db import models

class BranchOTP(models.Model):
    identifier   = models.CharField(max_length=255, db_index=True)  # Branch.email
    code_hash    = models.CharField(max_length=255)
    expires_at   = models.DateTimeField()
    used         = models.BooleanField(default=False)
    attempts     = models.PositiveIntegerField(default=0)
    sent_count   = models.PositiveIntegerField(default=1)
    last_sent_at = models.DateTimeField(auto_now=True)
    created_at   = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["identifier", "created_at"])]


class BranchStaff(models.Model):
    branch = models.ForeignKey(
        "Branch",
        on_delete=models.CASCADE,
        related_name="staff",
    )

    name = models.CharField(max_length=255)
    email = models.EmailField()

    # 🌟 NEW: staff ID (manual / user-created code)
    staff_id = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="Unique staff code created by branch",
    )

    # future mobile number
    mobile = models.CharField(max_length=20, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = (
            ("branch", "email"),
            ("branch", "staff_id"),   # 🌟 NEW: prevent duplicate staff codes per branch
        )

    def __str__(self):
        return f"{self.name} ({self.branch.name})"


# assume Branch model already defined above or imported from same app
# from .models import Branch  # if in another file


class ComplementaryOffer(models.Model):
    KIND_CHOICES = [
        ("complementary_offer", "Complementary Offer"),
    ]
    COUNT_START_CHOICES = [
        ("user_registration", "User registration date"),
        ("campaign_start", "Campaign start date"),
    ]

    # 🔥 New visit unit choices – ONLY qr modes
    VISIT_UNIT_CHOICES = [
        ("qr_screenshot", "QR scan + screenshot upload"),
        ("qr_pin", "QR scan + PIN at outlet"),
        ("qr_payment_proof", "QR scan + payment proof (bill amount / screenshot)"),
    ]

    DEDUPE_UNIT_CHOICES = [
        ("day", "day"),
        ("hour", "hour"),
        ("minute", "minute"),
    ]
    PER_USER_LIMIT_CHOICES = [
        ("per_multiple", "Once per eligible multiple"),
        ("once", "Once only (lifetime)"),
    ]
    ISSUANCE_MODE_CHOICES = [
        ("auto", "Auto-issue on eligibility"),
        ("claim", "Require Claim click"),
    ]
    REDEEM_TYPE_CHOICES = [
        ("code", "Unique code / QR"),
        ("manual", "Manual verify (staff PIN)"),
    ]
    SEGMENT_CHOICES = [
        ("all", "All users"),
        ("new_30", "New users (≤ 30 days)"),
        ("custom", "Custom"),
    ]

    # Basic
    kind = models.CharField(
        max_length=32,
        choices=KIND_CHOICES,
        default="complementary_offer",  # IMPORTANT: ee value
    )
    title = models.CharField(
        max_length=120,
        default="Complementary Offer",
    )
    is_active = models.BooleanField(default=True)

    # Eligibility · Visits
    count_start = models.CharField(
        max_length=32,
        choices=COUNT_START_CHOICES,
        default="user_registration",
    )
    backfill = models.BooleanField(default=False)

    nth = models.PositiveIntegerField(
        null=True,
        blank=True,
        default=None,
        help_text="Free on every Nth visit (optional).",
    )
    repeat = models.BooleanField(default=True)

    extra_nths = models.JSONField(default=list, blank=True)

    # 🚨 Important: default ni kotha value ki marcham
    visit_unit = models.CharField(
        max_length=16,
        choices=VISIT_UNIT_CHOICES,
        default="qr_screenshot",
    )

    dedupe_value = models.PositiveIntegerField(default=1)
    dedupe_unit = models.CharField(
        max_length=16,
        choices=DEDUPE_UNIT_CHOICES,
        default="day",
    )

    # (rest anni same unchavachu…)
    per_user_limit = models.CharField(
        max_length=16,
        choices=PER_USER_LIMIT_CHOICES,
        default="per_multiple",
    )
    claim_expiry_hours = models.PositiveIntegerField(default=24)

    total_cap = models.PositiveIntegerField(default=0)
    daily_cap = models.PositiveIntegerField(default=0)

    start_at = models.DateTimeField()
    end_at = models.DateTimeField(null=True, blank=True)

    active_from = models.TimeField(null=True, blank=True)
    active_to   = models.TimeField(null=True, blank=True)

    all_branches = models.BooleanField(default=False)
    eligible_branches = models.ManyToManyField(
        "Branch",
        blank=True,
        related_name="offers",
    )

    issuance_mode = models.CharField(
        max_length=16,
        choices=ISSUANCE_MODE_CHOICES,
        default="auto",
    )
    redeem_type   = models.CharField(
        max_length=16,
        choices=REDEEM_TYPE_CHOICES,
        default="code",
    )
    redeem_methods = models.CharField(
        max_length=64,
        blank=True,
        default="qr",
    )
    fallback_code_length = models.PositiveSmallIntegerField(default=6)

    segment = models.CharField(
        max_length=16,
        choices=SEGMENT_CHOICES,
        default="all",
    )
    exclude_admin = models.BooleanField(default=True)

    allow_key  = models.CharField(
        max_length=16,
        blank=True,
        default="",
    )
    allow_list = models.TextField(
        blank=True,
        default="",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # clean() and __str__ same unchavachu…

# ----------------------------------------------------

# ------------------------------------------------------
# user_logic



class LoginOTP(models.Model):
    email = models.EmailField(db_index=True)
    code_hash = models.CharField(max_length=128)        # sha256 hex (we won't store raw code)
    expires_at = models.DateTimeField()
    attempts = models.PositiveIntegerField(default=0)   # used later for verify
    used = models.BooleanField(default=False)

    # send throttling
    sent_count = models.PositiveIntegerField(default=0) # per recent window
    last_sent_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["email", "expires_at"])]

    def __str__(self):
        return f"{self.email} (used={self.used})"


User = get_user_model()

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    display_name = models.CharField(max_length=40, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.display_name or f"Profile({self.user_id})"




class UserLocationPing(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="location_pings")
    latitude  = models.DecimalField(max_digits=9, decimal_places=6)
    longitude = models.DecimalField(max_digits=9, decimal_places=6)
    accuracy_m = models.FloatField(null=True, blank=True)
    source = models.CharField(max_length=32, default="browser")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["user","-created_at"])]




class UserVisitEvent(models.Model):
    VISIT_METHOD_CHOICES = (
        ("qr_screenshot", "QR Screenshot Scan"),
        ("qr_pin", "QR PIN Entry"),
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="visit_events",
    )

    branch = models.ForeignKey(
        "Branch",
        on_delete=models.CASCADE,
        related_name="visit_events",
    )

    token = models.CharField(max_length=255, null=True, blank=True)
    desk = models.CharField(max_length=50, null=True, blank=True)

    visit_method = models.CharField(max_length=20, choices=VISIT_METHOD_CHOICES)

    # ⭐ NEW FIELDS
    staff_name = models.CharField(max_length=255, blank=True, default="")
    staff_code = models.CharField(max_length=100, blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        who = self.user or "Guest"
        return f"{who} @ {self.branch} ({self.visit_method})"




class BranchGenerateVisitPin(models.Model):
    branch = models.ForeignKey(
        "Branch",
        on_delete=models.CASCADE,
        related_name="generated_visit_pins",
    )
    desk = models.CharField(max_length=50, blank=True, default="")
    token = models.CharField(max_length=255, blank=True, default="")

    # PIN storage
    pin_hash = models.CharField(max_length=128)
    expires_at = models.DateTimeField()

    # 👉 used = real PIN usage (future verify view lo set chestham)
    used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)  # ← NEW

    # 👉 NEW: expired = time ayyi poindi, auto mark chestham
    expired = models.BooleanField(default=False)
    expired_at = models.DateTimeField(null=True, blank=True)  # ← NEW

    # optional snapshots
    staff_name = models.CharField(max_length=255, blank=True, default="")
    staff_code = models.CharField(max_length=100, blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.branch} / desk={self.desk} (visit PIN)"




class UserVerifyVisitPin(models.Model):
    branch = models.ForeignKey(
        "Branch",
        on_delete=models.CASCADE,
        related_name="user_verified_visit_pins",
    )

    desk = models.CharField(max_length=50, blank=True, default="")
    token = models.CharField(max_length=255, blank=True, default="")

    # 🔐 PIN hash (same pin multiple users try cheyyakunda audit kosam)
    pin_hash = models.CharField(max_length=128)

    # ⏳ validity
    expires_at = models.DateTimeField()

    # ✅ status
    used = models.BooleanField(default=False)
    expired = models.BooleanField(default=False)

    # 👤 USER SIDE info
    used_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="verified_visit_pins",
    )

    used_at = models.DateTimeField(null=True, blank=True)

    # 👨‍💼 staff snapshot (branch side)
    staff_name = models.CharField(max_length=255, blank=True, default="")
    staff_code = models.CharField(max_length=100, blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def mark_used(self, user=None):
        if not self.used:
            self.used = True
            self.used_by = user
            self.used_at = timezone.now()
            self.save(update_fields=["used", "used_by", "used_at"])

    def __str__(self):
        who = self.used_by.email if self.used_by else "Guest"
        return f"{self.branch} | {who} | PIN-used"



