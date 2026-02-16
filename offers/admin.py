# offers/admin.py
from django.contrib import admin
from django import forms
from django.http import HttpResponse
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
import csv

from .models import (
    Branch, BranchOTP, BranchStaff,
    ComplementaryOffer,
    LoginOTP, LoginVisit,
    Profile, UserLocationPing,
    QRToken, YashPin,
    UserVisitEvent,
    BranchGenerateVisitPin,
    UserVerifyVisitPin,
    UserOfferClaim,
    OfferDayPin,
)

# =========================
# Global helpers
# =========================
User = get_user_model()

def format_dt(dt):
    if not dt:
        return "-"
    return timezone.localtime(dt).strftime("%Y-%m-%d %H:%M:%S")


# =========================
# User (override default)
# =========================
admin.site.unregister(User)

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display  = ("id","username","email","first_name","last_name","is_staff","last_login","date_joined")
    list_filter   = BaseUserAdmin.list_filter
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
    ordering       = ("name",)
    list_filter    = ("created_at",)
    list_per_page  = 50

    fieldsets = (
        ("Identity", {"fields": ("public_id", "name", "email")}),
        ("Location (optional)", {"fields": ("latitude", "longitude")}),
        ("Meta", {"fields": ("created_at",)}),
    )

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
        if cleaned.get("all_branches"):
            cleaned["eligible_branches"] = []
        return cleaned


@admin.register(ComplementaryOffer)
class ComplementaryOfferAdmin(admin.ModelAdmin):
    form = ComplementaryOfferAdminForm

    list_display = (
        "id", "title", "kind", "visit_unit", "segment", "issuance_mode",
        "redeem_type", "is_active", "all_branches", "start_at", "end_at"
    )
    list_display_links = ("id", "title")
    list_filter = (
        "kind","visit_unit","segment","issuance_mode","redeem_type",
        "is_active","all_branches","start_at",
    )
    search_fields = ("title", "allow_list", "eligible_branches__name")
    readonly_fields = ("created_at", "updated_at")
    ordering = ("-created_at",)
    date_hierarchy = "start_at"
    list_per_page = 50

    filter_horizontal = ("eligible_branches",)

    def get_queryset(self, request):
        return super().get_queryset(request).prefetch_related("eligible_branches")

    def save_related(self, request, form, formsets, change):
        super().save_related(request, form, formsets, change)
        offer = form.instance
        if offer.all_branches:
            offer.eligible_branches.clear()


# =========================
# UserLocationPing (CSV export)
# =========================
@admin.register(UserLocationPing)
class UserLocationPingAdmin(admin.ModelAdmin):
    list_display = ("id", "user_display", "latitude", "longitude", "accuracy_m", "source", "created_at")
    list_display_links = ("id", "user_display")
    list_filter = ("source", "created_at")
    search_fields = ("user__username", "user__email", "user__first_name", "user__last_name")
    autocomplete_fields = ("user",)
    ordering = ("-created_at",)
    date_hierarchy = "created_at"
    list_per_page = 50
    readonly_fields = ("user", "latitude", "longitude", "accuracy_m", "source", "created_at")

    actions = ["export_as_csv"]

    def user_display(self, obj):
        u = obj.user
        name = (u.get_full_name() or u.first_name or u.username or u.email or str(u)).strip()
        return f"{name} ({u.id})"
    user_display.short_description = "User"

    def export_as_csv(self, request, queryset):
        resp = HttpResponse(content_type="text/csv")
        resp["Content-Disposition"] = 'attachment; filename="user_location_pings.csv"'
        writer = csv.writer(resp)
        writer.writerow(["id","user_id","username","email","latitude","longitude","accuracy_m","source","created_at"])
        for r in queryset.select_related("user"):
            writer.writerow([
                r.id, r.user_id,
                getattr(r.user, "username", ""),
                getattr(r.user, "email", ""),
                f"{r.latitude}", f"{r.longitude}",
                "" if r.accuracy_m is None else f"{r.accuracy_m:.2f}",
                r.source,
                r.created_at.isoformat(),
            ])
        return resp
    export_as_csv.short_description = "Export selected to CSV"


# =========================
# Profile
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

    def last_lat_disp(self, obj): return getattr(obj, "last_latitude", "")
    def last_lon_disp(self, obj): return getattr(obj, "last_longitude", "")
    def last_loc_at_disp(self, obj): return getattr(obj, "last_loc_at", "")

    last_lat_disp.short_description = "Last lat"
    last_lon_disp.short_description = "Last lon"
    last_loc_at_disp.short_description = "Last loc at"


# =========================
# OTPs (read-only)
# =========================
@admin.register(LoginOTP)
class LoginOTPAdmin(admin.ModelAdmin):
    list_display = ("id", "email", "used", "attempts", "expires_at", "last_sent_at", "created_at")
    search_fields = ("email",)
    list_filter = ("used", "expires_at", "created_at")
    ordering = ("-created_at",)
    list_per_page = 50

    readonly_fields = ("email", "code_hash", "expires_at", "attempts", "used", "sent_count", "last_sent_at", "created_at")


@admin.register(BranchOTP)
class BranchOTPAdmin(admin.ModelAdmin):
    list_display = ("id", "identifier", "used", "attempts", "expires_at", "last_sent_at", "created_at")
    search_fields = ("identifier",)
    list_filter = ("used", "expires_at", "created_at")
    ordering = ("-created_at",)
    list_per_page = 50

    readonly_fields = ("identifier", "code_hash", "expires_at", "attempts", "used", "sent_count", "last_sent_at", "created_at")


# =========================
# LoginVisit
# =========================
@admin.register(LoginVisit)
class LoginVisitAdmin(admin.ModelAdmin):
    list_display = ("id","user_display","visit_date","source","ip_address","short_user_agent","created_at")
    list_display_links = ("id","user_display")
    list_filter = ("source","visit_date","created_at")
    search_fields = ("user__username","user__email","user__first_name","user__last_name","ip_address")
    autocomplete_fields = ("user",)
    ordering = ("-created_at",)
    date_hierarchy = "visit_date"
    list_per_page = 50

    readonly_fields = ("user","visit_date","source","ip_address","user_agent","created_at")

    def user_display(self, obj):
        u = obj.user
        if not u:
            return "-"
        name = (u.get_full_name() or u.first_name or u.username or u.email or str(u)).strip()
        return f"{name} ({u.id})"
    user_display.short_description = "User"

    def short_user_agent(self, obj):
        ua = (obj.user_agent or "").strip()
        return "-" if not ua else (ua[:60] + "…" if len(ua) > 60 else ua)
    short_user_agent.short_description = "User-Agent"


# =========================
# QRToken + YashPin
# =========================
@admin.register(QRToken)
class QRTokenAdmin(admin.ModelAdmin):
    list_display = ("id","branch","desk","token_short","used","used_via","used_by","expires_at","used_at","created_at")
    list_filter  = ("branch","desk","used","used_via","expires_at","created_at")
    search_fields = ("token","branch__name","desk","staff_name","staff_code","used_by__email")
    ordering = ("-created_at",)
    list_per_page = 50
    autocomplete_fields = ("branch", "used_by")

    readonly_fields = ("created_at","used_at","last_seen_at")

    fieldsets = (
        ("Token Info", {"fields": ("branch","desk","token","expires_at")}),
        ("Usage Status", {"fields": ("used","used_via","used_by","used_at")}),
        ("Staff Snapshot", {"fields": ("staff_name","staff_code")}),
        ("Audit", {"fields": ("last_error","last_seen_at","created_at")}),
    )

    def token_short(self, obj):
        return obj.token[:10] + "..." if obj.token else "-"
    token_short.short_description = "Token"


@admin.register(YashPin)
class YashPinAdmin(admin.ModelAdmin):
    list_display = ("id","branch","desk","qr_token","used","used_by","expires_at","used_at","attempts","created_at")
    list_filter  = ("branch","desk","used","expires_at","created_at")
    search_fields = ("qr_token__token","branch__name","desk","staff_name","staff_code","used_by__email")
    ordering = ("-created_at",)
    list_per_page = 50
    autocomplete_fields = ("branch","qr_token","used_by")

    readonly_fields = ("pin_hash","created_at","used_at","last_attempt_at")

    fieldsets = (
        ("PIN Info", {"fields": ("branch","desk","qr_token","expires_at")}),
        ("Usage Status", {"fields": ("used","used_by","used_at")}),
        ("Security / Attempts", {"fields": ("pin_hash","attempts","last_attempt_at")}),
        ("Staff Snapshot", {"fields": ("staff_name","staff_code")}),
        ("Meta", {"fields": ("created_at",)}),
    )


# =========================
# UserVisitEvent
# =========================
@admin.register(UserVisitEvent)
class UserVisitEventAdmin(admin.ModelAdmin):
    list_display = ("id","user","branch","visit_method","desk","staff_name","staff_code","token","created_at")
    list_filter  = ("visit_method","branch","desk","staff_code","created_at")
    search_fields = ("token","desk","staff_name","staff_code","branch__name","user__username","user__email")
    ordering = ("-created_at",)
    date_hierarchy = "created_at"
    autocomplete_fields = ("user", "branch")

    readonly_fields = ("created_at",)

    fieldsets = (
        (None, {"fields": ("user","branch","visit_method","desk","staff_name","staff_code","token")}),
        ("Timestamps", {"fields": ("created_at",)}),
    )


# =========================
# BranchStaff
# =========================
@admin.register(BranchStaff)
class BranchStaffAdmin(admin.ModelAdmin):
    list_display = ("id","name","email","staff_id","branch","created_at")
    list_filter  = ("branch",)
    search_fields = ("name","email","staff_id")
    ordering = ("-id",)
    readonly_fields = ("created_at",)

    fieldsets = (
        ("Staff Details", {"fields": ("name","email","mobile","staff_id")}),
        ("Branch Info", {"fields": ("branch",)}),
        ("Meta", {"fields": ("created_at",)}),
    )


# =========================
# BranchGenerateVisitPin
# =========================
@admin.register(BranchGenerateVisitPin)
class BranchGenerateVisitPinAdmin(admin.ModelAdmin):
    list_display = ("id","branch","desk","token_short","staff_name","staff_code","used","expired","expires_at","created_at")
    list_filter  = ("branch","desk","used","expired","expires_at","created_at")
    search_fields = ("branch__name","desk","token","staff_name","staff_code")
    ordering = ("-created_at",)

    readonly_fields = ("pin_hash","created_at")

    fieldsets = (
        ("PIN Info", {"fields": ("branch","desk","token","staff_name","staff_code","used","expired","expires_at")}),
        ("Security / Meta", {"fields": ("pin_hash","created_at")}),
    )

    def token_short(self, obj):
        return obj.token[:10] + "..." if obj.token else "-"
    token_short.short_description = "Token"


# =========================
# UserVerifyVisitPin
# =========================
@admin.register(UserVerifyVisitPin)
class UserVerifyVisitPinAdmin(admin.ModelAdmin):
    list_display = ("id","branch","desk","token","used","expired","used_by","used_at","expires_at","created_at")
    list_filter  = ("used","expired","branch","created_at","used_at")
    search_fields = ("token","desk","branch__name","used_by__email","staff_name","staff_code")
    ordering = ("-created_at",)
    readonly_fields = ("created_at","used_at")



@admin.register(OfferDayPin)
class OfferDayPinAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "branch",
        "user",
        "desk",
        "used",
        "expires_at",
        "used_at",
        "used_by_staff_code",
        "created_at",
    )
    list_filter = ("used", "branch", "expires_at", "created_at")
    search_fields = ("branch__name", "branch__public_id", "user__email", "user__username", "desk", "token")
    ordering = ("-id",)
    list_per_page = 50

    # ✅ full read-only
    readonly_fields = (
        "branch","user","token","desk","pin_hash",
        "expires_at","used","used_at",
        "used_by_staff_id","used_by_staff_name","used_by_staff_code",
        "created_at",
    )

    fieldsets = (
        ("Core", {"fields": ("branch","user","desk","token")}),
        ("PIN / Validity", {"fields": ("pin_hash","expires_at")}),
        ("Usage", {"fields": ("used","used_at")}),
        ("Staff Snapshot", {"fields": ("used_by_staff_id","used_by_staff_name","used_by_staff_code")}),
        ("Meta", {"fields": ("created_at",)}),
    )

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False



@admin.register(UserOfferClaim)
class UserOfferClaimAdmin(admin.ModelAdmin):
    list_display = (
        "id","user","branch","offer",
        "milestone_kind","milestone_n",
        "status","issued_at","redeemed_at","token",
    )
    list_filter = ("status","milestone_kind","branch","offer","issued_at")
    search_fields = ("user__username","user__email","branch__name","token","desk","staff_name","staff_code")
    autocomplete_fields = ("user","branch","offer","visit_event")
    ordering = ("-issued_at",)
    date_hierarchy = "issued_at"
    list_per_page = 50
    readonly_fields = ("issued_at","redeemed_at")

    fieldsets = (
        ("Core", {"fields": ("user","branch","offer","visit_event","status")}),
        ("Milestone", {"fields": ("milestone_kind","milestone_n")}),
        ("Offer Snapshot", {"fields": ("offer_nth","offer_repeat","offer_extra_nths","offer_start_at","offer_end_at")}),
        ("Audit Mirrors", {"fields": ("token","desk","staff_name","staff_code")}),
        ("Timestamps", {"fields": ("issued_at","redeemed_at")}),
    )
