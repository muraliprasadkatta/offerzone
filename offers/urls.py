from django.urls import path
from . import admin_views as aviews
from . import user_views  as uviews
from . import branch_views as bviews
from .views_root import root_router   # ← Option B use chesthe: from .view import root_router
from django.urls import include, path
from . import qr_pin_service 




app_name = "offers"

urlpatterns = [

    path("", root_router, name="root"),

    path("user/login/",  uviews.user_login_page,  name="user_login"),
    path("auth/otp/send", uviews.otp_send, name="otp_send"),
    path("auth/otp/verify", uviews.otp_verify, name="otp_verify"),  # ← NEW
    path("user/home/",   uviews.user_home_page,  name="user_home"),
    path("logout/", uviews.user_logout_view, name="user_logout"),
    path("user/save-name", uviews.save_display_name, name="save_display_name"),
    path("user/save-location", uviews.save_location, name="save_location"),


    path("branches/search/", aviews.branches_search, name="branches_search"),
    path("branches/create/", aviews.branches_create, name="branches_create"), 
    path("admin/logout/", aviews.admin_logout_view, name="admin_logout"),
    path("admin/login/", aviews.admin_login_view, name="admin_login"),
    path("admin/home/", aviews.admin_home, name="admin_home"),            # ← /  is home
    path("complementary-offer/save", aviews.complementary_offer_save, name="complementary_offer_save"),
    # path("admin/api/qr/generate/",aviews.api_generate_counter_qr,name="api_generate_counter_qr",),
    path("admin/branch/<int:branch_id>/",aviews.branch_detail_view, name="branch_detail"),
    path("admin/branch/<int:branch_id>/offer-json/", aviews.offer_json_for_branch, name="offer_json_for_branch"),



    path("qrg/", include(("offers.qr_generation.urls", "qrgen"), namespace="qrgen")),

    path("branch/login/", bviews.branch_login_view, name="branch_login"), 
    path("branch/check",  bviews.branch_check_view, name="branch_check"),  # ← NEW
    path("branch/auth/otp/send", bviews.branch_otp_send, name="branch_otp_send"),
    path("branch/auth/otp/verify", bviews.branch_otp_verify, name="branch_otp_verify"),
    path("branch/home/", bviews.branch_home_view, name="branch_home"),
    path("branch/logout/", bviews.branch_logout_view, name="branch_logout"),
    path("branch/staff/create/",bviews.branch_staff_create_view,name="branch_staff_create"),


    # offers/urls.py
    path("qrg/pin-verify/", uviews.pin_verify, name="pin_verify"),
    path("qrg/scan-verify/", uviews.scan_verify, name="scan_verify"),

    path(
        "visit-count/intake/",uviews.user_visit_intake_redirect_view,name="user_visit_intake"),
        path("qrg/confirm-branch-visit/", uviews.confirm_branch_visit, name="confirm_branch_visit"),


    path("visit/pin/", uviews.user_visit_pin_page_view, name="user_visit_pin_page"),
    path("user-status/", uviews.user_status_view, name="user_status"),
    path(
        "visit-pin/verify/",
        uviews.user_verify_visit_pin,
        name="user_verify_visit_pin"
    ),


    path("branch_offers_in_userinterface/<int:branch_id>/",uviews.branch_offers_in_userinterface,name="branch_offers_in_userinterface"),


    path(
        "branch/visit-pin/generate/",
        qr_pin_service.branch_generate_visit_pin,
        name="branch_generate_visit_pin",
    ),

]
