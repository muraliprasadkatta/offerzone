# offers/admin.py
from django.contrib import admin
from django import forms
from django.http import HttpResponse
import csv

from .models import (
    ComplementaryOffer,
    Branch,
    BranchOTP,
    LoginVisit,
    LoginOTP,
    Profile,
    UserLocationPing,
    QRPin,
    QRTokenUsage, 
    UserVisitEvent, 
    BranchStaff,
    BranchGenerateVisitPin
    
)

from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils import timezone


User = get_user_model()
admin.site.unregister(User)

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('id','username','email','first_name','last_name','is_staff','last_login','date_joined')
    list_filter  = BaseUserAdmin.list_filter  # keep defaults
    search_fields = BaseUserAdmin.search_fields



# =========================
# Branch
# =========================

@admin.register(Branch)
class BranchAdmin(admin.ModelAdmin):
    list_display   = ("id", "public_id", "name", "email", "has_coords", "created_at")
    list_display_links = ("id", "name")
    search_fields  = ("name", "email", "public_id")
    readonly_fields = ("public_id", "created_at")
    list_per_page  = 50
    ordering       = ("name",)
    list_filter    = ("created_at",)

    fieldsets = (
        ("Identity", {
            "fields": ("public_id", "name", "email"),
            "description": "Public ID is auto-generated and immutable."
        }),
        ("Location (optional)", {
            "fields": ("latitude", "longitude"),
        }),
        ("Meta", {
            "fields": ("created_at",),
        }),
    )

    # little helper to show “has coordinates”
    def has_coords(self, obj):
        return bool(obj.latitude is not None and obj.longitude is not None)
    has_coords.boolean = True
    has_coords.short_description = "Coords?"


# =========================
# ComplementaryOffer
# =========================

class ComplementaryOfferAdminForm(forms.ModelForm):
    class Meta:
        model = ComplementaryOffer
        fields = "__all__"

    def clean(self):
        cleaned = super().clean()
        # mirror view logic: when all_branches=True, ignore eligible_branches selection
        if cleaned.get("all_branches"):
            cleaned["eligible_branches"] = []
        return cleaned


@admin.register(ComplementaryOffer)
class ComplementaryOfferAdmin(admin.ModelAdmin):
    form = ComplementaryOfferAdminForm

    list_display = (
        "id", "title", "kind", "segment", "issuance_mode",
        "redeem_type", "is_active", "all_branches", "start_at", "end_at"
    )
    list_display_links = ("id", "title")
    list_filter  = (
        "kind", "segment", "issuance_mode", "redeem_type",
        "is_active", "all_branches", "start_at",
    )
    search_fields = (
        "title",
        "allow_list",
        "eligible_branches__name",   # search by branch name
    )
    readonly_fields = ("created_at", "updated_at")
    date_hierarchy = "start_at"
    ordering = ("-created_at",)
    list_per_page = 50

    # If branch count is small:
    filter_horizontal = ("eligible_branches",)
    # If branches become 1000+, prefer this instead:
    # autocomplete_fields = ("eligible_branches",)

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.prefetch_related("eligible_branches")

    def save_related(self, request, form, formsets, change):
        super().save_related(request, form, formsets, change)
        offer = form.instance
        if offer.all_branches:
            offer.eligible_branches.clear()


# =========================
# UserLocationPing (with CSV export)
# =========================

@admin.register(UserLocationPing)
class UserLocationPingAdmin(admin.ModelAdmin):
    list_display = (
        "id", "user_display", "latitude", "longitude",
        "accuracy_m", "source", "created_at",
    )
    list_display_links = ("id", "user_display")
    list_filter = ("source", "created_at")
    search_fields = ("user__username", "user__email", "user__first_name", "user__last_name")
    autocomplete_fields = ("user",)
    ordering = ("-created_at",)
    date_hierarchy = "created_at"
    list_per_page = 50
    readonly_fields = ("user", "latitude", "longitude", "accuracy_m", "source", "created_at")

    def user_display(self, obj):
        u = obj.user
        name = (u.get_full_name() or u.first_name or u.username or u.email or str(u)).strip()
        return f"{name} ({u.id})"
    user_display.short_description = "User"

    actions = ["export_as_csv"]

    def export_as_csv(self, request, queryset):
        resp = HttpResponse(content_type="text/csv")
        resp["Content-Disposition"] = 'attachment; filename="user_location_pings.csv"'
        writer = csv.writer(resp)
        writer.writerow(["id","user_id","username","email","latitude","longitude","accuracy_m","source","created_at"])
        for r in queryset.select_related("user"):
            writer.writerow([
                r.id,
                r.user_id,
                getattr(r.user, "username", ""),
                getattr(r.user, "email", ""),
                f"{r.latitude}",
                f"{r.longitude}",
                "" if r.accuracy_m is None else f"{r.accuracy_m:.2f}",
                r.source,
                r.created_at.isoformat(),
            ])
        return resp
    export_as_csv.short_description = "Export selected to CSV"


# =========================
# Profile (safe getters – fields optional)
# =========================

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ("id", "user_display", "display_name", "last_lat_disp", "last_lon_disp", "last_loc_at_disp")
    search_fields = ("user__username", "user__email", "display_name")
    autocomplete_fields = ("user",)
    ordering = ("-id",)
    list_per_page = 50

    def user_display(self, obj):
        u = obj.user
        return (u.get_full_name() or u.first_name or u.username or u.email or str(u)).strip()
    user_display.short_description = "User"

    def last_lat_disp(self, obj):
        return getattr(obj, "last_latitude", "")
    def last_lon_disp(self, obj):
        return getattr(obj, "last_longitude", "")
    def last_loc_at_disp(self, obj):
        return getattr(obj, "last_loc_at", "")
    last_lat_disp.short_description = "Last lat"
    last_lon_disp.short_description = "Last lon"
    last_loc_at_disp.short_description = "Last loc at"


# =========================
# LoginOTP (read-only-ish)
# =========================

@admin.register(LoginOTP)
class LoginOTPAdmin(admin.ModelAdmin):
    list_display = ("id", "email", "used", "attempts", "expires_at", "last_sent_at", "created_at")
    search_fields = ("email",)
    list_filter = ("used", "expires_at", "created_at")
    ordering = ("-created_at",)
    readonly_fields = ("email", "code_hash", "expires_at", "attempts", "used", "sent_count", "last_sent_at", "created_at")
    list_per_page = 50


# =========================
# BranchOTP (read-only-ish)
# =========================

@admin.register(BranchOTP)
class BranchOTPAdmin(admin.ModelAdmin):
    list_display = ("id", "identifier", "used", "attempts", "expires_at", "last_sent_at", "created_at")
    search_fields = ("identifier",)
    list_filter = ("used", "expires_at", "created_at")
    ordering = ("-created_at",)
    readonly_fields = ("identifier", "code_hash", "expires_at", "attempts", "used", "sent_count", "last_sent_at", "created_at")
    list_per_page = 50



# =========================
# LoginVisit
# =========================

@admin.register(LoginVisit)
class LoginVisitAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user_display",
        "visit_date",
        "source",
        "ip_address",
        "short_user_agent",
        "created_at",
    )
    list_display_links = ("id", "user_display")
    list_filter = ("source", "visit_date", "created_at")
    search_fields = (
        "user__username",
        "user__email",
        "user__first_name",
        "user__last_name",
        "ip_address",
    )
    autocomplete_fields = ("user",)
    ordering = ("-created_at",)
    date_hierarchy = "visit_date"
    list_per_page = 50
    readonly_fields = (
        "user",
        "visit_date",
        "source",
        "ip_address",
        "user_agent",
        "created_at",
    )

    def user_display(self, obj):
        u = obj.user
        if not u:
            return "-"
        name = (u.get_full_name() or u.first_name or u.username or u.email or str(u)).strip()
        return f"{name} ({u.id})"
    user_display.short_description = "User"

    def short_user_agent(self, obj):
        if not obj.user_agent:
            return "-"
        ua = obj.user_agent.strip()
        return ua[:60] + "…" if len(ua) > 60 else ua
    short_user_agent.short_description = "User-Agent"


# =========================
# QRPin
# =========================

@admin.register(QRPin)
class QRPinAdmin(admin.ModelAdmin):
    list_display = ("id", "branch", "desk", "token_short", "used", "expires_at", "used_at", "attempts", "created_at")
    list_filter = ("branch", "desk", "used")
    search_fields = ("token", "branch__name", "desk")
    ordering = ("-created_at",)
    list_per_page = 50

    def token_short(self, obj):
        return obj.token[:10] + "..." if obj.token else "-"
    token_short.short_description = "Token"


def format_dt(dt):
    if not dt:
        return "-"
    return timezone.localtime(dt).strftime("%Y-%m-%d %H:%M:%S")


# =========================
# QrLandingEvent – QR scan details
# =========================



# admin.py

from django.contrib import admin
from .models import UserVisitEvent


@admin.register(UserVisitEvent)
class UserVisitEventAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "branch",
        "visit_method",
        "desk",
        "staff_name",
        "staff_code",
        "token",
        "created_at",
    )

    readonly_fields = ("created_at",)   # ⭐ DISPLAY IN ADMIN FORM

    fieldsets = (
        (None, {
            "fields": (
                "user",
                "branch",
                "visit_method",
                "desk",
                "staff_name",
                "staff_code",
                "token",
            )
        }),
        ("Timestamps", {
            "fields": ("created_at",),      # ⭐ SHOW HERE
        }),
    )

    list_filter = (
        "visit_method",
        "branch",
        "desk",
        "staff_code",
        "created_at",
    )

    search_fields = (
        "token",
        "desk",
        "staff_name",
        "staff_code",
        "branch__name",
        "user__username",
        "user__email",
    )

    date_hierarchy = "created_at"
    ordering = ("-created_at",)
    autocomplete_fields = ("user", "branch")


from django.contrib import admin
from .models import BranchStaff


@admin.register(BranchStaff)
class BranchStaffAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "email", "staff_id", "branch", "created_at")
    list_filter = ("branch",)
    search_fields = ("name", "email", "staff_id")
    ordering = ("-id",)

    # Read-only fields
    readonly_fields = ("created_at",)

    # Fields arrangement in admin form
    fieldsets = (
        ("Staff Details", {
            "fields": ("name", "email", "mobile", "staff_id")
        }),
        ("Branch Info", {
            "fields": ("branch",),
        }),
        ("Meta", {
            "fields": ("created_at",),
        }),
    )



@admin.register(BranchGenerateVisitPin)
class BranchGenerateVisitPinAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "branch",
        "desk",
        "token_short",
        "used",
        "expires_at",
        "created_at",
    )
    list_filter = ("branch", "desk", "used", "expires_at", "created_at")
    search_fields = ("branch__name", "desk", "token")
    ordering = ("-created_at",)
    list_per_page = 50
    readonly_fields = ("pin_hash", "created_at")

    fieldsets = (
        ("PIN Info", {
            "fields": ("branch", "desk", "token", "used", "expires_at")
        }),
        ("Security / Meta", {
            "fields": ("pin_hash", "created_at"),
            "description": "PIN hash is stored for security; original 4-digit PIN is never saved in plain text."
        }),
    )

    def token_short(self, obj):
        return obj.token[:10] + "..." if obj.token else "-"
    token_short.short_description = "Token"
