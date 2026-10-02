"""ABA Payway / KHQRPay client.

Implements the three documented technical solutions:

1. QR Checkout (redirect flow)
       GET  {api_base}/api/payment/requestv2/{profile_id}?...
2. Direct QR API (headless, server to server)
       POST {api_base}/api/{profile_id}/payment-gateway/v1/payments/qr-api-khqrcc
3. Verify / Check Transaction V2 (polling)
       POST {api_base}/api/{profile_id}/payment-gateway/v1/payments/check-transv2-khqrcc

plus the Callback / Webhook signature verification:
       sha256(secret + req_time + transaction_id + amount + "SUCCESS")
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal
from typing import Any
from urllib.parse import urlencode

import httpx

REQUEST_TIMEOUT = 25.0


# --------------------------------------------------------------------- helpers
def amount_str(amount: Any, decimals: int = 2) -> str:
    """Format an amount exactly the way it is hashed AND sent to ABA.

    The signature is a plain string concatenation, so the string form used for
    the hash and the form field MUST be byte-for-byte identical.
    """
    quant = Decimal(1).scaleb(-int(decimals))
    value = Decimal(str(amount)).quantize(quant, rounding=ROUND_HALF_UP)
    return f"{value:.{int(decimals)}f}"


def _sha1(*parts: str) -> str:
    return hashlib.sha1("".join(str(p) for p in parts).encode("utf-8")).hexdigest()


def _sha256(*parts: str) -> str:
    return hashlib.sha256("".join(str(p) for p in parts).encode("utf-8")).hexdigest()


def b64_encode(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _looks_base64(value: str) -> bool:
    try:
        base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(value) % 4 == 0 and len(value) >= 8


# --------------------------------------------------------------- hash builders
def checkout_hash(secret: str, transaction_id: str, amount: str, success_url: str, remark: str = "") -> str:
    """sha1(secret + transaction_id + amount + success_url + remark)."""
    return _sha1(secret, transaction_id, amount, success_url, remark or "")


def qr_hash(secret: str, transaction_id: str, amount: str, success_url: str, remark: str = "") -> str:
    """Same formula as the QR Checkout flow: sha1(secret + id + amount + success_url + remark)."""
    return _sha1(secret, transaction_id, amount, success_url, remark or "")


def verify_hash(secret: str, transaction_id: str) -> str:
    """sha1(secret + transaction_id)."""
    return _sha1(secret, transaction_id)


def callback_hash(secret: str, req_time: Any, transaction_id: str, amount: Any, status: str = "SUCCESS") -> str:
    """sha256(secret + req_time + transaction_id + amount + "SUCCESS")."""
    return _sha256(secret, req_time, transaction_id, amount, status)


def _first(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload and payload[key] not in (None, ""):
            return payload[key]
    return None


# --------------------------------------------------------------------- results
@dataclass
class GatewayResult:
    ok: bool
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    http_status: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "message": self.message,
            "data": self.data,
            "raw": self.raw,
            "http_status": self.http_status,
        }


class AbaPaywayError(RuntimeError):
    """Raised when the ABA gateway cannot be reached at all."""


class AbaPaywayClient:
    """Thin, dependency-light client around the ABA Payway KHQRcc endpoints."""

    def __init__(self, api_base: str, profile_id: str, secret_key: str, decimals: int = 2) -> None:
        self.api_base = (api_base or "").rstrip("/")
        self.profile_id = (profile_id or "").strip()
        self.secret_key = (secret_key or "").strip()
        self.decimals = int(decimals or 2)

    # ------------------------------------------------------------------ urls
    @property
    def configured(self) -> bool:
        """True when api base + profile id + secret key are all present."""
        return bool(self.api_base and self.profile_id and self.secret_key)

    def checkout_get_url(self) -> str:
        """GET {api_base}/api/payment/requestv2/{profile_id}"""
        return f"{self.api_base}/api/payment/requestv2/{self.profile_id}"

    def qr_api_url(self) -> str:
        """POST /api/{profile_id}/payment-gateway/v1/payments/qr-api-khqrcc"""
        return f"{self.api_base}/api/{self.profile_id}/payment-gateway/v1/payments/qr-api-khqrcc"

    def check_trans_url(self) -> str:
        """POST /api/{profile_id}/payment-gateway/v1/payments/check-transv2-khqrcc"""
        return (
            f"{self.api_base}/api/{self.profile_id}"
            "/payment-gateway/v1/payments/check-transv2-khqrcc"
        )

    def hosted_checkout_url(self) -> str:
        """The standalone checkout page (used by the JS plugin / deeplink)."""
        base = self.api_base.replace("//anajakpay.com", "//checkout.anajakpay.com")
        return f"{base}/payment/khqrcc/{self.profile_id}"

    # ------------------------------------------------------- 1. QR Checkout
    def build_checkout_url(
        self,
        transaction_id: str,
        amount: Any,
        success_url: str,
        remark: str = "",
        cancel_url: str | None = None,
        items: str | None = None,
        custom_fields: str | None = None,
        extra_query: str | None = None,
    ) -> str:
        """Build the signed redirect URL for the managed QR Checkout page."""
        amount_text = amount_str(amount, self.decimals)
        params: dict[str, str] = {
            "transaction_id": transaction_id,
            "amount": amount_text,
            "success_url": success_url,
            "remark": remark or "",
        }
        if cancel_url:
            params["cancel_url"] = cancel_url
        if items:
            params["items"] = items if _looks_base64(items) else b64_encode(items)
        if custom_fields:
            params["custom_fields"] = (
                custom_fields if _looks_base64(custom_fields) else b64_encode(custom_fields)
            )
        params["hash"] = checkout_hash(
            self.secret_key, transaction_id, amount_text, success_url, remark or ""
        )
        base = self.checkout_get_url()
        if extra_query:
            base = f"{base}?{extra_query.lstrip('?')}"
        separator = "&" if "?" in base else "?"
        return f"{base}{separator}{urlencode(params)}"

    # -------------------------------------------- 2. Direct QR API (headless)
    def create_qr(
        self,
        transaction_id: str,
        amount: Any,
        success_url: str,
        remark: str = "",
        cancel_url: str | None = None,
        items: str | None = None,
        custom_fields: str | None = None,
        timeout: float = REQUEST_TIMEOUT,
    ) -> GatewayResult:
        """POST to qr-api-khqrcc and return the raw KHQR string + PNG url."""
        amount_text = amount_str(amount, self.decimals)
        payload: dict[str, str] = {
            "transaction_id": transaction_id,
            "amount": amount_text,
            "success_url": success_url,
            "remark": remark or "",
        }
        if cancel_url:
            payload["cancel_url"] = cancel_url
        if items:
            payload["items"] = items if _looks_base64(items) else b64_encode(items)
        if custom_fields:
            payload["custom_fields"] = (
                custom_fields if _looks_base64(custom_fields) else b64_encode(custom_fields)
            )
        payload["hash"] = qr_hash(
            self.secret_key, transaction_id, amount_text, success_url, remark or ""
        )
        return self._post_form(self.qr_api_url(), payload, timeout=timeout)

    # -------------------------------------------- 3. Verify / Check V2 (poll)
    def check_transaction(self, transaction_id: str, timeout: float = REQUEST_TIMEOUT) -> GatewayResult:
        """Poll the fast v2 verification endpoint for a transaction."""
        payload = {
            "transaction_id": transaction_id,
            "hash": verify_hash(self.secret_key, transaction_id),
        }
        return self._post_form(self.check_trans_url(), payload, timeout=timeout)

    # -------------------------------------------------------------- transport
    def _post_form(
        self, url: str, payload: dict[str, str], timeout: float = REQUEST_TIMEOUT
    ) -> GatewayResult:
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                response = client.post(url, data=payload, headers={"Accept": "application/json"})
        except Exception as exc:  # network / DNS / TLS problems
            raise AbaPaywayError(f"Cannot reach ABA Payway at {url}: {exc}") from exc

        body: dict[str, Any] = {}
        text = response.text or ""
        try:
            parsed = response.json()
            body = parsed if isinstance(parsed, dict) else {"data": parsed}
        except (json.JSONDecodeError, ValueError):
            body = {"raw_text": text[:2000]}

        code = body.get("responseCode", body.get("response_code"))
        message = str(
            body.get("responseMessage")
            or body.get("response_message")
            or body.get("message")
            or (f"HTTP {response.status_code}" if response.status_code >= 400 else "OK")
        )
        data = body.get("data") if isinstance(body.get("data"), dict) else {}
        ok = response.status_code < 400 and (code in (0, "0", None))

        return GatewayResult(
            ok=bool(ok),
            message=message,
            data=data or {},
            raw=body,
            http_status=response.status_code,
        )

    # -------------------------------------------------------------- webhooks
    def verify_callback(self, payload: dict[str, Any], signoff: str | None = None) -> bool:
        """Best-effort verification of an incoming ABA callback signature.

        Documented formula::

            sha256(secret + req_time + transaction_id + amount + "SUCCESS")

        Field names differ slightly between gateway versions, so several
        aliases are accepted. Returns False when nothing can be verified.
        """
        if not self.secret_key:
            return False
        if str(payload.get("status", "SUCCESS")).upper() not in ("SUCCESS", "PAID", "0", "OK"):
            return False

        req_time = _first(payload, "req_time", "reqTime", "request_time", "time", "timestamp")
        tx_id = _first(payload, "transaction_id", "transactionId", "order_id", "orderId")
        amount = _first(payload, "amount", "total", "total_amount")
        if tx_id is None or amount is None:
            return False
        amount_text = amount if isinstance(amount, str) else amount_str(amount, self.decimals)

        candidates: set[str] = {signoff} if signoff else set()
        for key in ("hash", "signature", "sign", "success_hash"):
            value = payload.get(key)
            if value:
                candidates.add(str(value))
        candidates.discard(None)

        expected = {
            callback_hash(self.secret_key, req_time, str(tx_id), amount_text, "SUCCESS"),
            callback_hash(self.secret_key, req_time, str(tx_id), amount_text, "success"),
        }
        return bool(candidates & expected)
