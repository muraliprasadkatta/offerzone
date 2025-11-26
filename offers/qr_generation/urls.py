# offers/qr_generation/urls.py
from django.urls import path
from . import views

app_name = "qrgen"

urlpatterns = [
    path("start", views.start_counter_qr, name="start_counter_qr"),
    path("redeem/<str:token>", views.redeem_land, name="redeem_land"),
    path("t/<str:token>", views.redeem_land),  # ← alias for older scans
    
]
