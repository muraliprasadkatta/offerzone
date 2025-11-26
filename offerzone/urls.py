"""
URL configuration for offerzone project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.contrib import admin as django_admin     # <-- alias add


urlpatterns = [
    path("django-admin/", django_admin.site.urls),          # Django Admin genuine
    # or: path("offers/", include("offers.urls"))  # URL: /offers/login/
    path("", include(("offers.urls", "offers"), namespace="offers")),
    path("qrg/", include("offers.qr_generation.urls")),


]


