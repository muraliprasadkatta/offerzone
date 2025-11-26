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
)

from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

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
    list_display  = ("id", "user_display", "visit_date", "source", "created_at")
    list_filter   = ("source", "visit_date", "created_at")
    search_fields = ("user__username", "user__email", "user__first_name", "user__last_name")
    date_hierarchy = "visit_date"
    autocomplete_fields = ("user",)
    ordering = ("-visit_date", "-created_at")
    list_per_page = 50

    def user_display(self, obj):
        u = obj.user
        return (u.get_full_name() or u.first_name or u.username or u.email or str(u)).strip()
    user_display.short_description = "User"


# =========================
# QRPin
# =========================

@admin.register(QRPin)
class QRPinAdmin(admin.ModelAdmin):
    list_display = ("id", "branch", "desk", "token", "expires_at", "used_at", "attempts", "created_at")
    list_filter = ("branch", "desk")
    search_fields = ("token",)
