"""Application configuration.

Values are resolved in this order (first match wins):
    1. real environment variables
    2. the ``.env`` file next to this module
    3. the value stored in the SQLite ``settings`` table (editable from the POS UI)
    4. the DEFAULTS dictionary below
"""
from __future__ import annotations

import os
from pathlib import Path

try:  # python-dotenv is optional at runtime, only needed for .env support
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent / ".env")
except Exception:  # pragma: no cover - dotenv missing
    pass

BASE_DIR = Path(__file__).resolve().parent

# Keys that may be stored in the database and exposed / edited from the UI.
EDITABLE_SETTINGS = (
    "profile_id",
    "secret_key",
    "api_base",
    "success_url",
    "cancel_url",
    "frontend_base_url",
    "demo_mode",
)

DEFAULTS: dict[str, str] = {
    "merchant_name": "ABA POS Demo Store",
    "currency": "USD",
    # The ABA merchant credentials are deliberately NOT here any more: a
    # secret that lives in source code is a secret every copy of the code
    # shares. Supply them through backend_api/.env (see .env.example) or
    # save them once in the POS Settings page (they land in the database).
    "profile_id": "",
    "secret_key": "",
    "api_base": "https://anajakpay.com",
    "success_url": "http://localhost:3000/?payment=success",
    "cancel_url": "http://localhost:3000/?payment=cancel",
    "frontend_base_url": "http://localhost:3000",
    "demo_mode": "true",
    # Number of decimals used when turning an amount into the string that is
    # concatenated into the sha1 hash AND sent to the gateway. Both MUST match.
    "amount_decimals": "2",
}

_ENV_MAP = {
    "ABA_PROFILE_ID": "profile_id",
    "ABA_SECRET_KEY": "secret_key",
    "ABA_API_BASE": "api_base",
    "ABA_SUCCESS_URL": "success_url",
    "ABA_CANCEL_URL": "cancel_url",
    "FRONTEND_BASE_URL": "frontend_base_url",
    "ABA_DEMO_MODE": "demo_mode",
}


def env_overrides() -> dict[str, str]:
    """Return settings that were supplied through real env vars / .env."""
    out: dict[str, str] = {}
    for env_key, setting_key in _ENV_MAP.items():
        value = os.environ.get(env_key)
        if value is not None and str(value).strip() != "":
            out[setting_key] = str(value).strip()
    return out


def env_locked_keys() -> set[str]:
    """Settings that come from the environment and cannot be edited in the UI."""
    return set(env_overrides().keys())


def get_settings_snapshot(db_values: dict[str, str]) -> dict[str, str]:
    """Merge every source into a single flat settings dictionary."""
    merged = dict(DEFAULTS)
    merged.update({k: v for k, v in db_values.items() if v is not None})
    merged.update(env_overrides())
    return merged


# --- misc -----------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip() or f"sqlite:///{BASE_DIR / 'pos.db'}"
DEMO_MODE_FALLBACK = True


# --- security --------------------------------------------------------------
def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    try:
        return int(str(os.environ.get(name, "")).strip() or default)
    except (TypeError, ValueError):
        return default


# Browser origins allowed to call the API. A malicious website visited on the
# till must not be able to talk to the POS backend, so "*" is no longer the
# default; LAN addresses on the POS port stay allowed through the regex below.
CORS_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
    ).split(",")
    if o.strip()
]

# http://localhost:3000 or http://<private ip>:3000 - set POS_CORS_ORIGIN_REGEX=""
# to switch the regex off completely.
CORS_ORIGIN_REGEX = os.environ.get("POS_CORS_ORIGIN_REGEX")
if CORS_ORIGIN_REGEX is None:
    CORS_ORIGIN_REGEX = (
        r"^https?://(localhost|127\.0\.0\.1|\[::1\]"
        r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3}"
        r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(:\d+)?$"
    )
CORS_ORIGIN_REGEX = CORS_ORIGIN_REGEX.strip() or None

# Host header allow-list. "*" keeps the default uvicorn behaviour; set e.g.
# POS_ALLOWED_HOSTS="127.0.0.1,localhost,192.168.1.5" once you know your address.
ALLOWED_HOSTS = [
    h.strip()
    for h in (os.environ.get("POS_ALLOWED_HOSTS") or "*").split(",")
    if h.strip()
] or ["*"]

# Interactive docs expose the whole endpoint map - off unless you ask for them.
ENABLE_DOCS = _env_flag("POS_ENABLE_DOCS", False)

# Escape hatch for local debugging ONLY (never on a reachable machine).
AUTH_DISABLED = _env_flag("POS_AUTH_DISABLED", False)

# Login sessions expire after this many hours.
TOKEN_TTL_HOURS = max(1, _env_int("POS_TOKEN_TTL_HOURS", 12))

# First-run administrator (password is generated + printed when not set here).
ADMIN_USERNAME = (os.environ.get("POS_ADMIN_USERNAME") or "admin").strip() or "admin"
ADMIN_PASSWORD = (os.environ.get("POS_ADMIN_PASSWORD") or "").strip()

# Brute-force / request-flood protection.
LOGIN_MAX_ATTEMPTS = max(3, _env_int("POS_LOGIN_MAX_ATTEMPTS", 6))
LOGIN_WINDOW_SECONDS = max(30, _env_int("POS_LOGIN_WINDOW_SECONDS", 300))
REQUEST_RATE_PER_MINUTE = max(30, _env_int("POS_REQUEST_RATE_PER_MINUTE", 600))
WRITE_RATE_PER_MINUTE = max(10, _env_int("POS_WRITE_RATE_PER_MINUTE", 240))

# Largest JSON body accepted (a backup import needs some room).
MAX_BODY_BYTES = max(64, _env_int("POS_MAX_BODY_MB", 25)) * 1024 * 1024

# Recommended password length for POS users.
MIN_PASSWORD_LENGTH = max(8, _env_int("POS_MIN_PASSWORD_LENGTH", 8))

DEMO_MODE_FALLBACK = True
