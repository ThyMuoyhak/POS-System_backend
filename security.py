"""Authentication, authorisation, rate limiting and the audit trail.

Security model
--------------
* **Passwords** are never stored: PBKDF2-HMAC-SHA256 with a random per-user
  salt and a high iteration count.
* **Sessions** are opaque ``secrets.token_urlsafe(32)`` tokens handed to the
  browser and stored in the database only as a SHA-256 hash, with an absolute
  expiry (``POS_TOKEN_TTL_HOURS``).
* **Every** ``/api`` route requires a valid token (``Depends(require_user)``)
  except ``/api/health``, ``/api/auth/login`` and the ABA payment
  callback/redirect. Privileged routes additionally require the ``admin``
  role (``Depends(require_admin)``).
* A small in-memory limiter slows down password guessing, write floods and
  oversized bodies; every state-changing (and every rejected) request lands in
  ``audit_logs`` so you can see who created or changed what.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from config import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    AUTH_DISABLED,
    BASE_DIR,
    LOGIN_MAX_ATTEMPTS,
    LOGIN_WINDOW_SECONDS,
    MAX_BODY_BYTES,
    MIN_PASSWORD_LENGTH,
    REQUEST_RATE_PER_MINUTE,
    TOKEN_TTL_HOURS,
    WRITE_RATE_PER_MINUTE,
)
from database import get_db
from models import AuditLog, AuthToken, User, utcnow

PBKDF2_ITERATIONS = 260_000
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ROLES = ("admin", "cashier")

# Passwords that show up in every credential-stuffing list.
_WEAK_PASSWORDS = {
    "12345678",
    "123456789",
    "1234567890",
    "password",
    "password1",
    "passw0rd",
    "qwerty123",
    "qwertyuiop",
    "admin123",
    "administrator",
    "aba12345",
    "11111111",
    "00000000",
    "aaaaaaaa",
    "iloveyou",
    "letmein1",
    "changeme",
    "pos12345",
}

_PASSWORD_ALPHABET = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#%+?"


# =============================================================== passwords ===
def hash_password(password: str) -> str:
    """``pbkdf2_sha256$<iterations>$<salt hex>$<hash hex>``."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str | None) -> bool:
    """Constant-time password check that never raises on a broken hash."""
    if not password or not stored:
        return False
    try:
        algorithm, iterations, salt_hex, hash_hex = str(stored).split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(digest.hex(), hash_hex)


def password_problem(password: str, username: str | None = None) -> str | None:
    """Return a human readable reason why a password is unacceptable."""
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return f"The password must be at least {MIN_PASSWORD_LENGTH} characters long."
    if len(password) > 200:
        return "The password must be shorter than 200 characters."
    lowered = password.lower()
    if username and lowered == username.lower():
        return "The password must not be the same as the username."
    if lowered in _WEAK_PASSWORDS:
        return "That password is too common - pick something less predictable."
    if len(set(password)) < 4:
        return "Use at least 4 different characters in the password."
    return None


def random_password(length: int = 16) -> str:
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(length))


# =================================================================== tokens ===
def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def bearer_token(request: Request) -> str | None:
    """Read the caller's token from ``Authorization: Bearer`` or ``X-API-Key``.

    Tokens are deliberately *not* accepted in the query string: URLs end up in
    browser history, proxy logs and referrer headers.
    """
    header = request.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        candidate = header[7:].strip()
        if candidate:
            return candidate
    api_key = (request.headers.get("x-api-key") or "").strip()
    return api_key or None


def issue_token(
    db: Session,
    user: User,
    *,
    ttl_hours: float = TOKEN_TTL_HOURS,
    user_agent: str | None = None,
    ip: str | None = None,
) -> tuple[str, datetime]:
    """Create a session and return ``(token, expires_at)``."""
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    expires_at = now + int(max(1.0, ttl_hours) * 3600)
    db.add(
        AuthToken(
            user_id=user.id,
            token_hash=token_hash(token),
            created_at=now,
            expires_at=expires_at,
            last_used_at=now,
            user_agent=(user_agent or "")[:200] or None,
            ip=(ip or "")[:64] or None,
        )
    )
    user.last_login_at = utcnow()
    db.commit()
    return token, datetime.fromtimestamp(expires_at, timezone.utc)


def resolve_token(db: Session, token: str | None) -> User | None:
    """Return the user behind a token (``None`` when unknown / expired)."""
    if not token:
        return None
    row = db.query(AuthToken).filter(AuthToken.token_hash == token_hash(token)).first()
    if row is None:
        return None
    now = int(time.time())
    if row.expires_at and int(row.expires_at) <= now:
        db.delete(row)
        db.commit()
        return None
    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        return None
    if not row.last_used_at or now - int(row.last_used_at) > 60:
        row.last_used_at = now
        try:
            db.commit()
        except Exception:  # pragma: no cover - never break a request over this
            db.rollback()
    return user


def revoke_token(db: Session, token: str | None) -> None:
    if not token:
        return
    row = db.query(AuthToken).filter(AuthToken.token_hash == token_hash(token)).first()
    if row is not None:
        db.delete(row)
        db.commit()


def revoke_tokens(db: Session, user: User, keep: str | None = None) -> int:
    """Kill every session of ``user`` (optionally keeping the current one)."""
    query = db.query(AuthToken).filter(AuthToken.user_id == user.id)
    if keep:
        query = query.filter(AuthToken.token_hash != token_hash(keep))
    removed = 0
    for row in query.all():
        db.delete(row)
        removed += 1
    db.commit()
    return removed


def purge_expired_tokens(db: Session) -> int:
    """Housekeeping - drop sessions that expired or belong to deleted users."""
    now = int(time.time())
    rows = db.query(AuthToken).filter(AuthToken.expires_at <= now).all()
    for row in rows:
        db.delete(row)
    if rows:
        db.commit()
    return len(rows)


# ============================================================ user accounts ===
def username_problem(username: str) -> str | None:
    if not username or not (3 <= len(username) <= 32):
        return "The username must be 3-32 characters long."
    if not all(ch.isalnum() or ch in "._-@" for ch in username):
        return "Use letters, digits and . _ - @ only."
    return None


def get_user(db: Session, username: str) -> User | None:
    if not username:
        return None
    return db.query(User).filter(User.username.ilike(username.strip())).first()


def create_user(
    db: Session,
    *,
    username: str,
    password: str,
    role: str = "cashier",
    full_name: str | None = None,
) -> User:
    username = (username or "").strip()
    problem = username_problem(username)
    if problem:
        raise HTTPException(status_code=400, detail=problem)
    if role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Role must be one of {', '.join(ROLES)}")
    if get_user(db, username) is not None:
        raise HTTPException(status_code=409, detail=f"The username '{username}' already exists")
    problem = password_problem(password, username)
    if problem:
        raise HTTPException(status_code=400, detail=problem)

    user = User(
        username=username,
        full_name=(full_name or "").strip() or None,
        role=role,
        is_active=True,
        password_hash=hash_password(password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def set_password(db: Session, user: User, password: str, *, revoke_sessions: bool = True) -> None:
    problem = password_problem(password, user.username)
    if problem:
        raise HTTPException(status_code=400, detail=problem)
    user.password_hash = hash_password(password)
    db.commit()
    if revoke_sessions:
        revoke_tokens(db, user)


def count_active_admins(db: Session, exclude_id: int | None = None) -> int:
    query = db.query(User).filter(User.role == "admin", User.is_active.is_(True))
    if exclude_id is not None:
        query = query.filter(User.id != exclude_id)
    return query.count()


def guard_last_admin(db: Session, user: User, *, action: str) -> None:
    """Stop an admin from locking everybody out of the shop."""
    if (user.role or "").lower() != "admin" or not user.is_active:
        return
    others = [u for u in db.query(User).filter(User.role == "admin", User.is_active.is_(True)).all()]
    if len(others) <= 1:
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{user.username}' is the only active administrator - "
                f"create another one before you {action}."
            ),
        )


def authenticate(db: Session, username: str, password: str) -> User | None:
    """Return the matching active user, or ``None``."""
    user = get_user(db, username)
    if user is None:
        # Burn the same amount of CPU as a real check so usernames cannot be
        # enumerated by measuring response times.
        verify_password(password, hash_password("timing-equaliser"))
        return None
    if not verify_password(password, user.password_hash):
        return None
    if not user.is_active:
        return None
    return user


# ============================================================== rate limits ===
class SlidingWindowLimiter:
    """Tiny in-process limiter (no Redis needed for a single-till POS)."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._hits.get(key)
            if bucket is None:
                bucket = deque()
                self._hits[key] = bucket
            while bucket and bucket[0] <= now - window:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            if len(self._hits) > 4000:  # pragma: no cover - memory housekeeping
                for stale in [k for k, v in self._hits.items() if not v]:
                    self._hits.pop(stale, None)
            return True

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def retry_after(self, key: str, window: float) -> int:
        with self._lock:
            bucket = self._hits.get(key)
            if not bucket:
                return 0
            return max(1, int(window - (time.monotonic() - bucket[0])))

    def clear(self) -> None:  # pragma: no cover - used by tests
        with self._lock:
            self._hits.clear()


REQUEST_LIMITER = SlidingWindowLimiter()
WRITE_LIMITER = SlidingWindowLimiter()
LOGIN_LIMITER = SlidingWindowLimiter()


def client_ip(request: Request | None) -> str:
    if request is None or request.client is None:
        return "unknown"
    return request.client.host or "unknown"


def _login_key(request: Request, username: str) -> str:
    return f"login:{client_ip(request)}:{(username or '').strip().lower()}"


def login_allowed(request: Request, username: str) -> bool:
    return LOGIN_LIMITER.allow(
        _login_key(request, username), LOGIN_MAX_ATTEMPTS, float(LOGIN_WINDOW_SECONDS)
    )


def login_succeeded(request: Request, username: str) -> None:
    LOGIN_LIMITER.reset(_login_key(request, username))


def login_retry_after(request: Request, username: str) -> int:
    return LOGIN_LIMITER.retry_after(_login_key(request, username), float(LOGIN_WINDOW_SECONDS))


# ============================================================== dependencies ===
def _dev_user() -> User:
    """Placeholder identity used only when POS_AUTH_DISABLED=true."""
    user = User(username="auth-disabled", role="admin", is_active=True, password_hash="-")
    user.id = None
    return user


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """FastAPI dependency - 401 unless the request carries a valid token."""
    cached = getattr(request.state, "user", None)
    if cached is not None:
        return cached
    if AUTH_DISABLED:  # pragma: no cover - deliberate unsafe development mode
        user = _dev_user()
        request.state.user = user
        return user
    user = resolve_token(db, bearer_token(request))
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sign in to use the POS API.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    request.state.user = user
    return user


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Any signed-in operator (admin or cashier)."""
    return current_user(request, db)


def require_admin(request: Request, db: Session = Depends(get_db)) -> User:
    """Administrators only - catalogue, settings, users, backups."""
    user = current_user(request, db)
    if (user.role or "").lower() != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires an administrator account.",
        )
    return user


# =============================================================== audit trail ===
def log_audit(
    db: Session,
    *,
    user: User | None = None,
    action: str,
    request: Request | None = None,
    status_code: int | None = None,
    detail: str | None = None,
) -> None:
    """Append one row to ``audit_logs`` (never raises)."""
    try:
        db.add(
            AuditLog(
                at=int(time.time()),
                user_id=getattr(user, "id", None),
                username=(getattr(user, "username", None) or "anonymous")[:64],
                role=(getattr(user, "role", None) or "-")[:16],
                ip=client_ip(request)[:64],
                method=(request.method if request is not None else "")[:8] or None,
                path=(request.url.path if request is not None else "")[:200] or None,
                status_code=status_code,
                action=action[:60],
                detail=(detail or "")[:2000] or None,
            )
        )
        db.commit()
    except Exception:  # pragma: no cover - auditing must never break a request
        try:
            db.rollback()
        except Exception:
            pass


def _audit_request(request: Request, status_code: int) -> None:
    """Called by the middleware for every state-changing or rejected request."""
    user = getattr(request.state, "user", None)
    forced = bool(getattr(request.state, "audit_always", False))
    if request.method not in WRITE_METHODS and status_code not in (401, 403) and not forced:
        return
    detail = getattr(request.state, "audit_detail", None)
    if detail is None and request.method in WRITE_METHODS:
        query = request.url.query
        detail = f"?{query}" if query else None
    from database import SessionLocal  # local import keeps this module import-safe

    db = SessionLocal()
    try:
        action = getattr(request.state, "audit_action", None) or f"{request.method} {request.url.path}"
        log_audit(db, user=user, action=action, request=request, status_code=status_code, detail=detail)
    finally:
        db.close()


# ================================================================ middleware ===
def _json_error(code: int, detail: str, retry_after: int | None = None) -> JSONResponse:
    headers = {"Retry-After": str(retry_after)} if retry_after else None
    response = JSONResponse(status_code=code, content={"detail": detail}, headers=headers)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def _harden_response(request: Request, response) -> None:
    headers = response.headers
    headers["X-Content-Type-Options"] = "nosniff"
    headers["X-Frame-Options"] = "DENY"
    headers["Referrer-Policy"] = "no-referrer"
    headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    headers["Cross-Origin-Resource-Policy"] = "same-site"
    if request.url.path.startswith("/api"):
        headers["Cache-Control"] = "no-store"
        headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    if request.url.scheme == "https":  # pragma: no cover - TLS is deployment specific
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"


class SecurityMiddleware(BaseHTTPMiddleware):
    """Body-size guard, rate limiting, audit trail and response hardening."""

    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":  # CORS pre-flight carries no credentials
            return await call_next(request)

        ip = client_ip(request)
        length = request.headers.get("content-length")
        if (
            request.method in WRITE_METHODS
            and length
            and length.isdigit()
            and int(length) > MAX_BODY_BYTES
        ):
            return _json_error(
                413, f"Request body is larger than {MAX_BODY_BYTES // (1024 * 1024)} MB."
            )

        if not REQUEST_LIMITER.allow(f"all:{ip}", REQUEST_RATE_PER_MINUTE, 60.0):
            return _json_error(429, "Too many requests - slow down.", retry_after=60)
        if request.method in WRITE_METHODS and not WRITE_LIMITER.allow(
            f"write:{ip}", WRITE_RATE_PER_MINUTE, 60.0
        ):
            return _json_error(429, "Too many write requests - slow down.", retry_after=60)

        response = await call_next(request)
        _harden_response(request, response)
        _audit_request(request, response.status_code)
        return response


# ================================================================= bootstrap ===
def ensure_bootstrap_admin(db: Session, *, printer=print) -> None:
    """Create the first administrator exactly once, then stay out of the way."""
    if db.query(User).count():
        purge_expired_tokens(db)
        return

    password = ADMIN_PASSWORD or random_password()
    db.add(
        User(
            username=ADMIN_USERNAME,
            full_name="Owner",
            role="admin",
            is_active=True,
            password_hash=hash_password(password),
        )
    )
    db.commit()

    if ADMIN_PASSWORD:
        printer(f"[security] Created the administrator '{ADMIN_USERNAME}' from POS_ADMIN_PASSWORD.")
        return

    printer(
        "\n"
        "==============================================================\n"
        " ABA POS first run - administrator account created\n"
        f"   username: {ADMIN_USERNAME}\n"
        f"   password: {password}\n"
        " Sign in once and change this password (Security tab).\n"
        " Lost it? On the server run:  python manage.py passwd admin\n"
        "==============================================================\n"
    )
    try:
        note = BASE_DIR / "initial_admin_password.txt"
        note.write_text(
            "ABA POS first-run administrator\n"
            f"username: {ADMIN_USERNAME}\npassword: {password}\n\n"
            "Sign in, change this password in the Security tab, then delete this file.\n",
            encoding="utf-8",
        )
        printer(f"[security] Password also written to {note} - delete it after you sign in.")
    except Exception:  # pragma: no cover - read-only filesystem
        pass
