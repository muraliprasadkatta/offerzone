from django.shortcuts import redirect
from django.urls import reverse
from django.views.decorators.cache import never_cache


@never_cache
def root_router(request):
    # 1) Branch session active → branch home
    if request.session.get("branch_id"):
        return redirect(reverse("offers:branch_home"))

    # 2) Logged-in Django user → route by role
    if request.user.is_authenticated:
        if request.user.is_superuser:
            return redirect(reverse("offers:admin_home"))
        return redirect(reverse("offers:user_home"))

    # 3) Optional explicit role hint for login pages
    role = (request.GET.get("role") or "").strip().lower()

    if role == "branch":
        return redirect(reverse("offers:branch_login"))

    if role == "admin":
        return redirect(reverse("offers:admin_login"))

    # 4) Default for guest user → public dashboard
    return redirect(reverse("offers:user_home"))