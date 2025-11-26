import hashlib, hmac, secrets, re
from datetime import timedelta
from django.conf import settings
from django.utils import timezone

OTP_TTL_MINUTES = 5
RESEND_COOLDOWN_SECONDS = 60
MAX_RESENDS_PER_15M = 3

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def normalize_email(e: str) -> str:
    return (e or "").strip().lower()

def valid_email(e: str) -> bool:
    return bool(EMAIL_RE.match(normalize_email(e)))

def gen_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"   # 000000–999999 (leading zeros ok)

def hash_code(email: str, code: str) -> str:
    secret = getattr(settings, "SECRET_KEY", "otp-secret")
    msg = f"{normalize_email(email)}::{code}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()

def now():
    return timezone.now()

def expires_at():
    return now() + timedelta(minutes=OTP_TTL_MINUTES)

def in_cooldown(last_sent_at):
    if not last_sent_at:
        return False, 0
    diff = (now() - last_sent_at).total_seconds()
    wait = max(0, RESEND_COOLDOWN_SECONDS - int(diff))
    return (wait > 0), wait
