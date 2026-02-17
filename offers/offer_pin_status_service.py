from django.http import JsonResponse
from django.views.decorators.http import require_GET
from django.views.decorators.cache import never_cache, cache_control
from django.contrib.auth.decorators import login_required
from django.urls import reverse

from offers.models import OfferDayPin


@require_GET
@login_required
@never_cache
@cache_control(no_cache=True, no_store=True, must_revalidate=True)
def user_offer_pin_status(request, offer_pin_id: int):
    row = (
        OfferDayPin.objects
        .filter(id=int(offer_pin_id), user_id=request.user.id)
        .only("id", "used", "expires_at")
        .first()
    )

    if not row:
        return JsonResponse({"ok": False, "error": "not_found"}, status=404)

    return JsonResponse({
        "ok": True,
        "offer_pin_id": row.id,
        "used": bool(row.used),
        "redirect_url": reverse("offers:user_status"),
    })
