# D:\restarent_application50\offers\services\visit_unit\visit_confirm.py

from dataclasses import dataclass
from typing import Optional

from django.db import transaction
from django.utils import timezone

from offers.models import QRToken, UserVisitEvent, YashPin


@dataclass
class ConfirmResult:
    ok: bool
    already_claimed_today: bool = False
    error: str = ""
    qr_token_id: Optional[int] = None
    branch_id: Optional[int] = None
    token: str = ""


def confirm_qr_code_visit(
    *,
    user,
    token: str,
    used_via: str = "scan",   # "scan" | "pin"
    now_ts=None,
) -> ConfirmResult:
    """
    Confirm visit immediately for visit_unit="qr_code".

    Atomic:
      - lock QRToken
      - validate not expired/used
      - enforce one-per-day per-branch
      - burn QRToken
      - create UserVisitEvent with visit_method="qr_code"
    """
    if not user or not getattr(user, "is_authenticated", False):
        return ConfirmResult(ok=False, error="Authentication required.")

    token = (token or "").strip()
    if not token:
        return ConfirmResult(ok=False, error="No QR token provided.")

    now_ts = now_ts or timezone.now()

    used_via = (used_via or "scan").strip().lower()
    if used_via not in ("scan", "pin"):
        used_via = "scan"

    with transaction.atomic():
        qt = (
            QRToken.objects
            .select_for_update()
            .select_related("branch")
            .filter(token=token)
            .first()
        )
        if not qt:
            return ConfirmResult(ok=False, error="QR not found. Please generate again.")

        if qt.expires_at and qt.expires_at <= now_ts:
            return ConfirmResult(ok=False, error="QR expired. Please generate again.")

        if qt.used:
            return ConfirmResult(ok=False, error="QR already used.")

        # one-per-day per-branch
        start_of_day = now_ts.replace(hour=0, minute=0, second=0, microsecond=0)
        already = UserVisitEvent.objects.filter(
            user=user,
            branch_id=qt.branch_id,
            created_at__gte=start_of_day,
        ).exists()

        if already:
            return ConfirmResult(
                ok=True,
                already_claimed_today=True,
                qr_token_id=qt.id,
                branch_id=qt.branch_id,
                token=qt.token,
            )

        # burn QRToken
        qt.used = True
        qt.used_at = now_ts
        qt.used_via = used_via
        qt.used_by = user
        qt.save(update_fields=["used", "used_at", "used_via", "used_by"])

        # create visit event
        UserVisitEvent.objects.create(
            user=user,
            branch_id=qt.branch_id,
            token=qt.token,
            desk=qt.desk or "",
            visit_method="qr_code",
            staff_name=getattr(qt, "staff_name", "") or "",
            staff_code=getattr(qt, "staff_code", "") or "",
        )

        return ConfirmResult(
            ok=True,
            already_claimed_today=False,
            qr_token_id=qt.id,
            branch_id=qt.branch_id,
            token=qt.token,
        )


def confirm_qr_code_visit_with_yashpin(
    *,
    user,
    yashpin_id: int,
    used_via: str = "pin",
    now_ts=None,
) -> ConfirmResult:
    """
    Confirm visit in qr_code mode using a YashPin row.

    Atomic:
      - lock YashPin row
      - validate not used/expired
      - lock its QRToken
      - validate QRToken not used/expired
      - enforce one-per-day per-branch
      - burn QRToken + mark YashPin used
      - create UserVisitEvent with visit_method="qr_code"
    """
    if not user or not getattr(user, "is_authenticated", False):
        return ConfirmResult(ok=False, error="Authentication required.")

    if not yashpin_id:
        return ConfirmResult(ok=False, error="Invalid PIN reference.")

    now_ts = now_ts or timezone.now()

    used_via = (used_via or "pin").strip().lower()
    if used_via not in ("scan", "pin"):
        used_via = "pin"

    with transaction.atomic():
        yp = (
            YashPin.objects
            .select_for_update()
            .select_related("qr_token", "branch")
            .filter(id=yashpin_id)
            .first()
        )
        if not yp:
            return ConfirmResult(ok=False, error="PIN not found.")

        if getattr(yp, "used", False):
            return ConfirmResult(ok=False, error="PIN already used. Please ask staff for a new PIN.")

        if getattr(yp, "expires_at", None) and yp.expires_at <= now_ts:
            return ConfirmResult(ok=False, error="PIN expired. Please ask staff for a new PIN.")

        qt0 = getattr(yp, "qr_token", None)
        if not qt0:
            return ConfirmResult(ok=False, error="QR missing for this PIN. Please try again.")

        # lock QRToken too (avoid race)
        qt = (
            QRToken.objects
            .select_for_update()
            .select_related("branch")
            .filter(id=qt0.id)
            .first()
        )
        if not qt:
            return ConfirmResult(ok=False, error="QR not found. Please generate again.")

        if qt.expires_at and qt.expires_at <= now_ts:
            return ConfirmResult(ok=False, error="QR expired. Please generate again.")

        if qt.used:
            return ConfirmResult(ok=False, error="QR already used.")

        # one-per-day per-branch
        start_of_day = now_ts.replace(hour=0, minute=0, second=0, microsecond=0)
        already = UserVisitEvent.objects.filter(
            user=user,
            branch_id=qt.branch_id,
            created_at__gte=start_of_day,
        ).exists()

        if already:
            return ConfirmResult(
                ok=True,
                already_claimed_today=True,
                qr_token_id=qt.id,
                branch_id=qt.branch_id,
                token=qt.token,
            )

        # burn QRToken
        qt.used = True
        qt.used_at = now_ts
        qt.used_via = used_via
        qt.used_by = user
        qt.save(update_fields=["used", "used_at", "used_via", "used_by"])

        # burn YashPin (safe fields)
        yp.used = True
        # only set these if model has them
        if hasattr(yp, "used_at"):
            yp.used_at = now_ts
        if hasattr(yp, "used_by"):
            yp.used_by = user

        upd = ["used"]
        if hasattr(yp, "used_at"):
            upd.append("used_at")
        if hasattr(yp, "used_by"):
            upd.append("used_by")
        yp.save(update_fields=upd)

        # create visit event
        UserVisitEvent.objects.create(
            user=user,
            branch_id=qt.branch_id,
            token=qt.token,
            desk=qt.desk or "",
            visit_method="qr_code",
            staff_name=getattr(qt, "staff_name", "") or "",
            staff_code=getattr(qt, "staff_code", "") or "",
        )

        return ConfirmResult(
            ok=True,
            already_claimed_today=False,
            qr_token_id=qt.id,
            branch_id=qt.branch_id,
            token=qt.token,
        )


def clear_pending_qr_session(request) -> None:
    """
    Convenience helper: clear all pending locks used in scan/pin flows.
    Safe to call always.
    """
    for k in (
        "pending_qr_token",
        "pending_qr_branch_id",
        "pending_qr_branch_name",
        "pending_qr_desk",
        "pending_qr_started_at",
        "pending_pin_row_id",
        "pending_qr_method",
    ):
        request.session.pop(k, None)


def set_last_branch_session(
    request,
    *,
    branch_id: int,
    branch_name: str,
    token: str,
    desk: str = "",
) -> None:
    """
    Convenience helper: update last_* session keys after confirm.
    """
    request.session["last_branch_id"] = branch_id
    request.session["last_branch_name"] = branch_name
    request.session["last_visit_token"] = token
    if desk is not None:
        request.session["last_branch_desk"] = desk
    request.session["last_qr_ok_at"] = timezone.now().isoformat()