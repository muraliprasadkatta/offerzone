from django.db import models

# Create your models here.
# app: offers/models.py
from django.db import models
from django.utils import timezone
# at top of models.py & utils_qr.py
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models
from django.db.models.functions import Lower
from django.core.exceptions import ValidationError
from decimal import Decimal, ROUND_HALF_UP
from django.db import models



from django.db import models
from django.contrib.auth import get_user_model


# offers/models.py
from django.utils import timezone

from django.utils import timezone  # already undi anukunta


from django.db import models
from django.utils import timezone

class QRPin(models.Model):
    branch = models.ForeignKey(
        "offers.Branch",           # string ref ok
        on_delete=models.CASCADE,
        related_name="qr_pins",
    )
    desk = models.CharField(
        max_length=12,
        blank=True,
        default="",
        help_text="Optional desk/counter label, e.g. A1, Main, Cash-1",
    )

    # QR token itself
    token = models.CharField(
        max_length=200,
        unique=True,              # token globally unique
        db_index=True,
    )

    # PIN ni plain ga kaakunda hash store cheddam
    pin_hash = models.CharField(
        max_length=128,
    )

    used = models.BooleanField(default=False)          # 👈 ADD THIS

    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    # future use kosam
    used_at = models.DateTimeField(null=True, blank=True)
    attempts = models.PositiveSmallIntegerField(default=0)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"QRPin({self.branch_id}, {self.desk}, {self.token[:8]}...)"


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

    class Meta:
        unique_together = (("user", "visit_date"),)   # ✅ 1/day de-dupe
        indexes = [
            models.Index(fields=["user", "visit_date"]),
        ]

    def __str__(self):
        return f"{self.user_id}@{self.visit_date} ({self.source})"



# offers/models.py
from django.db import models

from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.functions import Lower

import secrets

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


class Branch(models.Model):
    name = models.CharField(
        max_length=120,
        unique=True,
        validators=[branch_name_validator],
        help_text="lowercase a–z and 0–9 only; no spaces",
    )
    email = models.EmailField(blank=True, null=True, db_index=True)

    # ✅ Stable public unique id for QR/links
    # top: imports lo secrets alphabet & helper already unnaayi ani anukuntunna
    public_id = models.CharField(
        max_length=12,
        unique=True,              # enforce uniqueness
        default=make_branch_pid,  # auto-generate for new rows
        editable=False,
        db_index=True,
        help_text="Stable public identifier for URLs/QR (immutable)."
    )



    # ✅ manual coords (no auto-geo)
    latitude = models.DecimalField(
        max_digits=9, decimal_places=6,
        null=True, blank=True,
        validators=[MinValueValidator(Decimal("-90")), MaxValueValidator(Decimal("90"))],
        help_text="decimal degrees (−90..90) — 6 d.p."
    )
    longitude = models.DecimalField(
        max_digits=9, decimal_places=6,
        null=True, blank=True,
        validators=[MinValueValidator(Decimal("-180")), MaxValueValidator(Decimal("180"))],
        help_text="decimal degrees (−180..180) — 6 d.p."
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(Lower('name'), name='uniq_branch_name_lower'),
        ]
        indexes = [
            models.Index(Lower('name'), name='idx_branch_name_lower'),
            models.Index(fields=['latitude', 'longitude'], name='idx_branch_lat_lon'),
            # public_id ki separate db_index already undi; malli index add avasaram ledu
        ]

    def clean(self):
        """Normalize name and enforce coord pair + rounding."""
        # --- name normalize + regex ---
        if self.name:
            raw = self.name.strip()
            norm = ''.join(ch for ch in raw.lower() if ch.isalnum())
            if not norm:
                raise ValidationError({"name": branch_name_validator.message})
            self.name = norm
            branch_name_validator(self.name)

        # --- coord pair rule (both or none) ---
        lat = self.latitude
        lon = self.longitude
        if (lat is None) ^ (lon is None):
            raise ValidationError("Provide both latitude and longitude, or leave both empty")

        # --- round to 6 dp consistently ---
        def r6(v):
            return v.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
        if lat is not None:
            self.latitude = r6(Decimal(lat))
        if lon is not None:
            self.longitude = r6(Decimal(lon))

    def save(self, *args, **kwargs):
        # Ensure normalization even if clean() not called
        if self.name:
            self.name = ''.join(ch for ch in self.name.strip().lower() if ch.isalnum())

        # mirror the rounding if values are present
        def r6(v):
            return v.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
        if self.latitude is not None and not isinstance(self.latitude, Decimal):
            self.latitude = r6(Decimal(self.latitude))
        if self.longitude is not None and not isinstance(self.longitude, Decimal):
            self.longitude = r6(Decimal(self.longitude))

        super().save(*args, **kwargs)

    def __str__(self):
        return self.name

    @property
    def coords(self):
        return (float(self.latitude), float(self.longitude)) if (self.latitude is not None and self.longitude is not None) else None

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

from django.db import models

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

# offers/models.py
from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    display_name = models.CharField(max_length=40, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.display_name or f"Profile({self.user_id})"


# offers/models.py
from django.conf import settings
from django.db import models

class UserLocationPing(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="location_pings")
    latitude  = models.DecimalField(max_digits=9, decimal_places=6)
    longitude = models.DecimalField(max_digits=9, decimal_places=6)
    accuracy_m = models.FloatField(null=True, blank=True)
    source = models.CharField(max_length=32, default="browser")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["user","-created_at"])]
