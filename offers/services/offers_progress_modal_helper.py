# offers/services/offers_progress_modal_helper.py

from __future__ import annotations

from typing import Any, Dict, List, Optional


def _suffix(n: int) -> str:
    """1st/2nd/3rd/4th..."""
    if 10 <= (n % 100) <= 20:
        return "th"
    return {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")


def _to_int_list(xs) -> List[int]:
    out: List[int] = []
    if not xs:
        return out
    for v in xs:
        try:
            n = int(v)
        except (TypeError, ValueError):
            continue
        if n > 0:
            out.append(n)
    return sorted(set(out))


def offers_progress_modal_context(
    *,
    total_visits: int,
    nth: Optional[int],
    repeat: bool,
    extra_nths: Optional[List[int]] = None,
    max_preview: int = 15,
    include_repeat_multiples: bool = True,   # ✅ default ON (repeat=true unte 2N,3N.. track lo chustam)
    progress_span_mode: str = "max",         # ✅ "nth" OR "max"
) -> Dict[str, Any]:
    """
    Build UI-ready context for offers_progress_modal.

    Inputs:
      - total_visits: user's total verified visits at this branch
      - nth: main milestone (e.g., 5)
      - repeat: repeats every nth or one-time
      - extra_nths: manual milestones (e.g., [6,9,15])
      - max_preview: preview boxes up to this visit number
      - include_repeat_multiples: repeat=true ayithe track/rows lo 2N,3N.. add cheyyala?
      - progress_span_mode:
          "nth" -> bar is 0..nth (classic: 2/5)
          "max" -> bar is 0..max milestone in this config (better when extras like 25 exist)

    Returns keys:
      has_milestones, points_label,
      nth, repeat, extra_nths,
      current_progress, progress_total, progress_pct,
      preview_boxes, rows, milestones
    """

    # -------------------------
    # sanitize inputs
    # -------------------------
    try:
        total_visits_i = int(total_visits or 0)
    except Exception:
        total_visits_i = 0
    if total_visits_i < 0:
        total_visits_i = 0

    nth_i: Optional[int] = None
    if nth is not None and str(nth).strip() != "":
        try:
            nth_i = int(nth)
        except (TypeError, ValueError):
            nth_i = None
    if nth_i is not None and nth_i <= 0:
        nth_i = None

    try:
        mp = int(max_preview or 0)
    except Exception:
        mp = 0
    if mp < 0:
        mp = 0

    extra = _to_int_list(extra_nths)

    has_milestones = bool(nth_i or extra)

    # No milestones configured
    if not has_milestones:
        return {
            "has_milestones": False,
            "points_label": f"{total_visits_i}+",
            "nth": 0,
            "repeat": bool(repeat),
            "extra_nths": [],
            "current_progress": 0,
            "progress_total": 0,
            "progress_pct": 0,
            "preview_boxes": [],
            "rows": [],
            "milestones": [],
        }

    # -------------------------
    # Build milestone visit numbers
    # main nth + extras
    # (optional) include multiples of nth for repeat
    # -------------------------
    milestone_visits: List[int] = []

    if nth_i:
        milestone_visits.append(nth_i)

        # ✅ Optional: repeat markers 2N,3N.. (until max_preview)
        if repeat and include_repeat_multiples and mp > 0:
            k = 2
            while (nth_i * k) <= mp:
                milestone_visits.append(nth_i * k)
                k += 1

    milestone_visits.extend(extra)
    milestone_visits = sorted(set([v for v in milestone_visits if v > 0]))

    # -------------------------
    # Determine active milestone = nearest upcoming milestone
    # -------------------------
    upcoming = [v for v in milestone_visits if v > total_visits_i]
    active_target = min(upcoming) if upcoming else None

    def state_for(v: int) -> str:
        """
        done   -> already crossed
        active -> next upcoming milestone
        lock   -> future (not next)
        """
        if total_visits_i >= v:
            return "done"
        if active_target is not None and v == active_target:
            return "active"
        return "lock"

    def icon_for(v: int, is_main: bool) -> str:
        st = state_for(v)
        if st == "done":
            return "✓"
        if st == "active":
            return "⭐" if is_main else "🎯"
        return "🔒"

    # -------------------------
    # progress bar
    # -------------------------
    # mode "nth": show progress within cycle (repeat) OR until nth (one-time)
    # mode "max": show progress towards max milestone in config (nice when extras exist)
    current_progress = 0
    progress_total = 0
    progress_pct = 0

    if nth_i and progress_span_mode == "nth":
        progress_total = nth_i
        if repeat:
            current_progress = (total_visits_i % nth_i) or (nth_i if total_visits_i else 0)
        else:
            current_progress = min(total_visits_i, nth_i)
        progress_pct = int(round((current_progress / progress_total) * 100)) if progress_total else 0

    else:
        # "max" mode (default): progress towards max milestone
        progress_total = max(milestone_visits) if milestone_visits else (nth_i or 0)
        if progress_total:
            current_progress = min(total_visits_i, progress_total)
            progress_pct = int(round((current_progress / progress_total) * 100))
        else:
            current_progress = 0
            progress_pct = 0

    # -------------------------
    # rows list
    # -------------------------
    rows: List[Dict[str, Any]] = []
    for v in milestone_visits:
        is_main = bool(nth_i and v == nth_i)
        rows.append(
            {
                "visit_no": v,
                "label": f"{v}{_suffix(v)} visit",
                "state": state_for(v),
                "is_main": is_main,
                "icon": icon_for(v, is_main),
                "title": "Free Treat" if is_main else "Extra Treat!",
                "date_label": "",  # later fill if you store achieved dates
            }
        )

    # -------------------------
    # top track milestones (positions)
    # span = max milestone shown on track
    # -------------------------
    span = max(milestone_visits) if milestone_visits else (nth_i or 1)
    span = max(span, nth_i or 1)

    def left_pct(v: int) -> int:
        pct = int(round((v / span) * 100))
        return max(12, min(96, pct))

    milestones: List[Dict[str, Any]] = []
    for v in milestone_visits:
        is_main = bool(nth_i and v == nth_i)
        milestones.append(
            {
                "visit_no": v,
                "label": f"{v}{_suffix(v)}",
                "left_pct": left_pct(v),
                "state": state_for(v),
                "is_main": is_main,
            }
        )

    # -------------------------
    # preview boxes 1..max_preview
    # -------------------------
    preview_boxes: List[Dict[str, Any]] = []
    for v in range(1, mp + 1):
        kind = "normal"

        if nth_i and v == nth_i:
            kind = "main"
        elif v in extra:
            kind = "extra"

        # one-time: after nth => locked
        if nth_i and (not repeat) and v > nth_i:
            kind = "locked"

        if v in milestone_visits:
            st = state_for(v)
        else:
            st = "done" if total_visits_i >= v else "normal"

        preview_boxes.append({"visit_no": v, "kind": kind, "state": st})

    return {
        "has_milestones": True,
        "points_label": f"{total_visits_i}+",
        "nth": nth_i or 0,
        "repeat": bool(repeat),
        "extra_nths": extra,
        "current_progress": current_progress,
        "progress_total": progress_total,
        "progress_pct": progress_pct,
        "preview_boxes": preview_boxes,
        "rows": rows,
        "milestones": milestones,
    }
