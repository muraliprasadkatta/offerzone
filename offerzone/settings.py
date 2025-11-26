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

# Local development kosam .env nundi values load avuthayi.
# Railway lo normal env variables nundi directly tiskuntundi.
load_dotenv(BASE_DIR / ".env")

# -------------------------------------------------------------------
# CORE SECURITY / DEBUG
# -------------------------------------------------------------------
# SECRET_KEY: production lo .env / Railway env lo compulsory ga set cheyyi
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-prod")

# DEBUG: .env / Railway env lo DEBUG=true/false
DEBUG = os.getenv("DEBUG", "true").lower() == "true"

# ALLOWED_HOSTS: comma-separated list from env
# e.g. ALLOWED_HOSTS=offerzone-production.up.railway.app,localhost,127.0.0.1
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")

# CSRF_TRUSTED_ORIGINS: comma-separated list from env
# e.g. CSRF_TRUSTED_ORIGINS=https://offerzone-production.up.railway.app
_csrf_env = os.getenv("CSRF_TRUSTED_ORIGINS", "")
if _csrf_env:
    CSRF_TRUSTED_ORIGINS = [
        x.strip() for x in _csrf_env.split(",") if x.strip()
    ]
else:
    CSRF_TRUSTED_ORIGINS = []


# -------------------------------------------------------------------
# EMAIL (OTP / NOTIFICATIONS) - all from env
# -------------------------------------------------------------------
# Local dev lo: console backend use cheyyi
# Prod lo: smtp backend set cheyyi (e.g. Gmail)
EMAIL_BACKEND = os.getenv(
    "EMAIL_BACKEND",
    "django.core.mail.backends.console.EmailBackend",
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
        "DIRS": [BASE_DIR / "templates"],  # templates/ folder use cheyyalo ante
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
# DATABASE (SQLite for local, Postgres/other for deploy)
# -------------------------------------------------------------------
# Railway / Render lo DATABASE_URL env set chesthe automatic ga adhi use avuthundi.
DATABASES = {
    "default": dj_database_url.config(
        default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}",
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
QR_JWT_SECRET = os.getenv("QR_JWT_SECRET", "change-me-long-random")
QR_JWT_ISSUER = "offerzone"
QR_TTL_SECONDS = int(os.getenv("QR_TTL_SECONDS", "30"))  # rotate every 30s

QR_TTL_SECS = 180  # 3 minutes
OZ_QR_PIN_SALT = "oz.qrpin.salt.v1"


# -------------------------------------------------------------------
# SECURITY / PROXY (Railway / Render / ngrok)
# -------------------------------------------------------------------
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# cookies: production lo secure, local lo normal
if DEBUG:
    CSRF_COOKIE_SECURE = False
    SESSION_COOKIE_SECURE = False
else:
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_SECURE = True
