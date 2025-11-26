from django.shortcuts import redirect
from django.urls import reverse
from django.views.decorators.cache import never_cache
from django.utils.http import url_has_allowed_host_and_scheme

def _safe_next(request):
    nxt = request.GET.get("next") or "/"
    if url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        return nxt
    return "/"

@never_cache
def root_router(request):
    # 1) Already in a branch session → branch home
    if request.session.get("branch_id"):
        return redirect(reverse("offers:branch_home"))

    # 2) Logged-in Django user → route by role
    if request.user.is_authenticated:
        if getattr(request.user, "is_admin", False):
            return redirect(reverse("offers:admin_home"))
        return redirect(reverse("offers:user_home"))

    # 3) Not logged in: honor explicit role hint if present
    role = (request.GET.get("role") or "").strip().lower()
    nxt  = _safe_next(request)

    if role == "branch":
        # explicit branch login
        url = reverse("offers:branch_login")
        return redirect(f"{url}?next={nxt}" if nxt and nxt != "/" else url)

    if role == "admin":
        url = reverse("offers:admin_login")
        return redirect(f"{url}?next={nxt}" if nxt and nxt != "/" else url)

    # 4) DEFAULT: go to USER login (you asked for this)
    url = reverse("offers:user_login")
    return redirect(f"{url}?next={nxt}" if nxt and nxt != "/" else url)
