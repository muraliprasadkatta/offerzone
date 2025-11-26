# e file logins lo emina issue unte e file ni read cheyali 

# === GUARD:BRANCH_POLICY === single source of truth for branch/admin access
from functools import wraps
from django.http import JsonResponse, HttpResponseRedirect
from django.urls import reverse

def _wants_json(request):
    return request.headers.get("x-requested-with") == "XMLHttpRequest" or \
           "application/json" in request.headers.get("content-type", "")

def has_branch_session(request) -> bool:
    return bool(request.session.get("branch_id"))

def require_branch_session(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if has_branch_session(request):
            return view_func(request, *args, **kwargs)
        if _wants_json(request):
            return JsonResponse({"ok": False, "error": "Branch auth required"}, status=401)
        return HttpResponseRedirect(reverse("offers:branch_login"))
    return _wrapped

def require_branch_or_admin(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        ok = has_branch_session(request) or (
            request.user.is_authenticated and (request.user.is_staff or request.user.is_superuser)
        )
        if ok:
            return view_func(request, *args, **kwargs)
        if _wants_json(request):
            return JsonResponse({"ok": False, "error": "Auth required"}, status=401)
        return HttpResponseRedirect(reverse("offers:branch_login"))
    return _wrapped

def get_branch_from_session(request):
    return {"id": request.session.get("branch_id"),
            "name": request.session.get("branch_name")}
