"""
Django settings for offerzone project.
"""

from pathlib import Path
import os
from dotenv import load_dotenv
import dj_database_url

# -------------------------------------------------------------------
# BASE + ENV LOADING
# -------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")   # .env nundi values load avuthayi

# -------------------------------------------------------------------
# CORE SECURITY / DEBUG
# -------------------------------------------------------------------
# Production lo .env lo SECRET_KEY must
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-prod")

# DEBUG: .env lo DEBUG=true/false
DEBUG = os.getenv("DEBUG", "true").lower() == "true"

# ALLOWED_HOSTS: comma-separated list from .env
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")

# CSRF_TRUSTED_ORIGINS: comma-separated list from .env
_csrf_env = os.getenv("CSRF_TRUSTED_ORIGINS", "")
if _csrf_env:
    CSRF_TRUSTED_ORIGINS = [
        x.strip() for x in _csrf_env.split(",") if x.strip()
    ]
else:
    CSRF_TRUSTED_ORIGINS = []


# -------------------------------------------------------------------
# EMAIL (OTP / NOTIFICATIONS) - all from .env
# -------------------------------------------------------------------
EMAIL_BACKEND = os.getenv(
    "EMAIL_BACKEND",
    "django.core.mail.backends.console.EmailBackend",  # default: console (local dev)
)
EMAIL_HOST = os.getenv("EMAIL_HOST", "")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS", "true").lower() == "true"
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD", "")
DEFAULT_FROM_EMAIL = os.getenv(
    "DEFAULT_FROM_EMAIL",
    EMAIL_HOST_USER or "no-reply@example.local",
)


# -------------------------------------------------------------------
# DJANGO APPS / MIDDLEWARE
# -------------------------------------------------------------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "offers.apps.OffersConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "offerzone.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "offerzone.wsgi.application"


# -------------------------------------------------------------------
# DATABASE (SQLite for local, Postgres for deploy)
# -------------------------------------------------------------------
DATABASES = {
    "default": dj_database_url.config(
        default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}",  # .env lo DATABASE_URL unte adi use avthundi
        conn_max_age=600,
    )
}


# -------------------------------------------------------------------
# AUTH / PASSWORDS
# -------------------------------------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# -------------------------------------------------------------------
# I18N / TIMEZONE
# -------------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Kolkata"
USE_I18N = True
USE_TZ = True


# -------------------------------------------------------------------
# STATIC FILES
# -------------------------------------------------------------------
STATIC_URL = "static/"
# deploy kosam static root (e.g. Render)
STATIC_ROOT = BASE_DIR / "staticfiles"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# -------------------------------------------------------------------
# LOGIN / REDIRECTS
# -------------------------------------------------------------------
LOGIN_URL = "/user/login/"
LOGIN_REDIRECT_URL = "/user/home"


# -------------------------------------------------------------------
# QR / OTP RELATED
# -------------------------------------------------------------------
QR_JWT_SECRET = os.getenv("QR_JWT_SECRET", "change-me-long-random")  # prod lo change cheyyi
QR_JWT_ISSUER = "offerzone"
QR_TTL_SECONDS = int(os.getenv("QR_TTL_SECONDS", "30"))  # rotate every 30s

QR_TTL_SECS = 180  # 3 minutes
OZ_QR_PIN_SALT = "oz.qrpin.salt.v1"  # just any constant string


# -------------------------------------------------------------------
# SECURITY / PROXY (ngrok / render / etc)
# -------------------------------------------------------------------
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# cookies: production lo secure, local lo normal (default via DEBUG + env)
if DEBUG:
    CSRF_COOKIE_SECURE = False
    SESSION_COOKIE_SECURE = False
else:
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_SECURE = True


# ===================================================================
# 🔰 LOCAL vs DEPLOY OVERRIDE BLOCKS
#    -> CONFUSE KAAKUNDA CLEAR GA CHESINAM
#    -> Need ayithe ekkada uncomment cheyyi, inko block comment lo vey.
# ===================================================================

# ----------------- 🧪 LOCAL DEVELOPMENT (run on your laptop) -----------------
# DEBUG = True
# ALLOWED_HOSTS = ["localhost", "127.0.0.1"]
# CSRF_TRUSTED_ORIGINS = [
#     "http://localhost:8000",
#     "http://127.0.0.1:8000",
# ]
# CSRF_COOKIE_SECURE = False
# SESSION_COOKIE_SECURE = False
# EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"  # or keep smtp if you want real mails


# ----------------- 🚀 DEPLOY / PRODUCTION (Render/Railway etc.) --------------
# DEBUG = False
# ALLOWED_HOSTS = ["offerzone.onrender.com"]   # <-- mee actual domain ikkad pettu
# CSRF_TRUSTED_ORIGINS = [
#     "https://offerzone.onrender.com",
# ]
# CSRF_COOKIE_SECURE = True
# SESSION_COOKIE_SECURE = True
# EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
