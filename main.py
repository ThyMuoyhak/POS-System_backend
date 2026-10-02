"""ABA POS - FastAPI backend.

Run with:  uvicorn main:app --reload --port 8000
Docs at:   http://127.0.0.1:8000/docs  (only when POS_ENABLE_DOCS=true)

Security
--------
Every ``/api`` route requires a bearer token obtained from
``POST /api/auth/login``. Only ``/api/health``, ``/api/auth/login`` and the ABA
webhook/redirect stay public (the webhook is protected by its signature
instead). Mutating routes and administrator-only routes are flagged in the
decorators below with ``security.require_user`` / ``security.require_admin``.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

import crud
import security
from aba_payway import AbaPaywayError
from config import (
    ALLOWED_HOSTS,
    AUTH_DISABLED,
    CORS_ORIGIN_REGEX,
    CORS_ORIGINS,
    EDITABLE_SETTINGS,
    ENABLE_DOCS,
    TOKEN_TTL_HOURS,
    env_locked_keys,
)
from database import get_db, init_db
from models import (
    AuditLog,
    Category,
    Order,
    OrderItem,
    Product,
    User,
    WebhookLog,
    money,
    utcnow,
)
from schemas import (
    AuditOut,
    CategoryCreate,
    CategoryOut,
    CategoryUpdate,
    ChangePasswordRequest,
    ImportRequest,
    LoginRequest,
    LoginResult,
    Message,
    OrderCreate,
    OrderCreateResult,
    OrderOut,
    PaymentCheckResult,
    ProductCreate,
    ProductOut,
    ProductUpdate,
    SettingsOut,
    SettingsUpdate,
    UserCreateRequest,
    UserOut,
    UserUpdateRequest,
)

app = FastAPI(
    title="ABA POS API",
    version="1.0.0",
    description=(
        "Small POS system (products, categories, cash + KHQR payments) with the "
        "ABA Payway / KHQRPay gateway integrated (QR Checkout, Direct QR API, "
        "Verify V2 and Callback/Webhook)."
    ),
    # The interactive docs list every endpoint - keep them off until asked for.
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url="/redoc" if ENABLE_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None,
)

# Outermost layer first: rate limits + audit + headers, then host filtering,
# then CORS (so even error responses carry the CORS headers the browser needs).
app.add_middleware(security.SecurityMiddleware)

if ALLOWED_HOSTS != ["*"]:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS or ["*"],
    allow_origin_regex=CORS_ORIGIN_REGEX,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-API-Key"],
    expose_headers=["Content-Disposition"],
)

api = APIRouter(prefix="/api")


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    from database import SessionLocal

    db = SessionLocal()
    try:
        crud.seed_demo_data(db)
        # Creates the first administrator (and prints/writes its password) only
        # when no user exists yet - see backend_api/security.py.
        security.ensure_bootstrap_admin(db)
        if AUTH_DISABLED:  # pragma: no cover
            print(
                "[security] WARNING: POS_AUTH_DISABLED=true - every endpoint is open "
                "to anybody who can reach this machine. Never do this in the shop."
            )
    finally:
        db.close()


@app.get("/", include_in_schema=False)
def root() -> dict:
    payload = {"name": "ABA POS API", "version": app.version, "auth": "Bearer token required"}
    if ENABLE_DOCS:
        payload["docs"] = "/docs"
    return payload


@api.get("/health", tags=["system"])
def health() -> dict:
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


# ============================================================== categories ===
@api.get(
    "/categories",
    tags=["categories"],
    response_model=list[CategoryOut],
    dependencies=[Depends(security.require_user)],
)
def list_categories(db: Session = Depends(get_db)):
    counts = dict(
        db.query(Product.category_id, func.count(Product.id)).group_by(Product.category_id).all()
    )
    rows = db.query(Category).order_by(Category.name).all()
    out = []
    for row in rows:
        data = row.as_dict()
        data["product_count"] = int(counts.get(row.id, 0))
        out.append(data)
    return out


@api.post(
    "/categories",
    tags=["categories"],
    response_model=CategoryOut,
    status_code=201,
    dependencies=[Depends(security.require_admin)],
)
def create_category(payload: CategoryCreate, db: Session = Depends(get_db)):
    name = payload.name.strip()
    if db.query(Category.id).filter(func.lower(Category.name) == name.lower()).first():
        raise HTTPException(status_code=409, detail=f"Category '{name}' already exists")
    category = Category(name=name, description=payload.description, color=payload.color)
    db.add(category)
    db.commit()
    db.refresh(category)
    return category.as_dict()


@api.put(
    "/categories/{category_id}",
    tags=["categories"],
    response_model=CategoryOut,
    dependencies=[Depends(security.require_admin)],
)
def update_category(category_id: int, payload: CategoryUpdate, db: Session = Depends(get_db)):
    category = db.get(Category, category_id)
    if category is None:
        raise HTTPException(status_code=404, detail="Category not found")
    if payload.name is not None:
        name = payload.name.strip()
        clash = (
            db.query(Category.id)
            .filter(func.lower(Category.name) == name.lower(), Category.id != category_id)
            .first()
        )
        if clash:
            raise HTTPException(status_code=409, detail=f"Category '{name}' already exists")
        category.name = name
    if payload.description is not None:
        category.description = payload.description
    if payload.color is not None:
        category.color = payload.color
    db.commit()
    db.refresh(category)
    return category.as_dict()


@api.delete(
    "/categories/{category_id}",
    tags=["categories"],
    response_model=Message,
    dependencies=[Depends(security.require_admin)],
)
def delete_category(category_id: int, db: Session = Depends(get_db)):
    category = db.get(Category, category_id)
    if category is None:
        raise HTTPException(status_code=404, detail="Category not found")
    linked = db.query(Product.id).filter(Product.category_id == category_id).count()
    if linked:
        raise HTTPException(
            status_code=400,
            detail=f"Category is used by {linked} product(s). Move or delete them first.",
        )
    db.delete(category)
    db.commit()
    return {"detail": "Category deleted"}


# ================================================================ products ===
@api.get(
    "/products",
    tags=["products"],
    response_model=list[ProductOut],
    dependencies=[Depends(security.require_user)],
)
def list_products(
    db: Session = Depends(get_db),
    search: str | None = Query(default=None, description="Match title, sku or description"),
    category_id: int | None = Query(default=None),
    active_only: bool = Query(default=False),
    in_stock_only: bool = Query(default=False),
    limit: int = Query(default=500, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
):
    query = db.query(Product)
    if search:
        like = f"%{search.strip()}%"
        query = query.filter(
            or_(Product.title.ilike(like), Product.sku.ilike(like), Product.description.ilike(like))
        )
    if category_id:
        query = query.filter(Product.category_id == category_id)
    if active_only:
        query = query.filter(Product.is_active.is_(True))
    if in_stock_only:
        query = query.filter(Product.stock > 0)
    rows = query.order_by(Product.title).offset(offset).limit(limit).all()
    return [row.as_dict() for row in rows]


@api.get(
    "/products/{product_id}",
    tags=["products"],
    response_model=ProductOut,
    dependencies=[Depends(security.require_user)],
)
def get_product(product_id: int, db: Session = Depends(get_db)):
    product = db.get(Product, product_id)
    if product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    return product.as_dict()


@api.post(
    "/products",
    tags=["products"],
    response_model=ProductOut,
    status_code=201,
    dependencies=[Depends(security.require_admin)],
)
def create_product(payload: ProductCreate, db: Session = Depends(get_db)):
    if payload.category_id is not None and db.get(Category, payload.category_id) is None:
        raise HTTPException(status_code=400, detail="Category not found")
    if payload.sku:
        clash = db.query(Product.id).filter(Product.sku == payload.sku.strip()).first()
        if clash:
            raise HTTPException(status_code=409, detail=f"SKU '{payload.sku}' already exists")
    product = Product(
        title=payload.title.strip(),
        description=payload.description,
        image_url=payload.image_url,
        sku=(payload.sku or "").strip() or None,
        price=money(payload.price),
        discount=round(payload.discount, 2),
        stock=payload.stock,
        category_id=payload.category_id,
        is_active=payload.is_active,
    )
    db.add(product)
    db.commit()
    db.refresh(product)
    return product.as_dict()


@api.put(
    "/products/{product_id}",
    tags=["products"],
    response_model=ProductOut,
    dependencies=[Depends(security.require_admin)],
)
def update_product(product_id: int, payload: ProductUpdate, db: Session = Depends(get_db)):
    product = db.get(Product, product_id)
    if product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    data = payload.model_dump(exclude_unset=True)
    if "category_id" in data and data["category_id"] is not None:
        if db.get(Category, data["category_id"]) is None:
            raise HTTPException(status_code=400, detail="Category not found")
    if data.get("sku"):
        sku = data["sku"].strip()
        clash = (
            db.query(Product.id)
            .filter(Product.sku == sku, Product.id != product_id)
            .first()
        )
        if clash:
            raise HTTPException(status_code=409, detail=f"SKU '{sku}' already exists")
        product.sku = sku
    elif "sku" in data:
        product.sku = None

    for field in ("title", "description", "image_url", "is_active", "category_id"):
        if field in data:
            value = data[field]
            if field == "title" and value is not None:
                value = value.strip()
            setattr(product, field, value)
    if "price" in data and data["price"] is not None:
        product.price = money(data["price"])
    if "discount" in data and data["discount"] is not None:
        product.discount = round(data["discount"], 2)
    if "stock" in data and data["stock"] is not None:
        product.stock = int(data["stock"])

    db.commit()
    db.refresh(product)
    return product.as_dict()


@api.delete(
    "/products/{product_id}",
    tags=["products"],
    response_model=Message,
    dependencies=[Depends(security.require_admin)],
)
def delete_product(product_id: int, db: Session = Depends(get_db)):
    product = db.get(Product, product_id)
    if product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    db.delete(product)
    db.commit()
    return {"detail": "Product deleted"}


@api.post(
    "/products/{product_id}/stock",
    tags=["products"],
    response_model=ProductOut,
    dependencies=[Depends(security.require_admin)],
)
def adjust_stock(product_id: int, amount: int = Query(...), db: Session = Depends(get_db)):
    """Add (positive) or remove (negative) stock in one call."""
    product = db.get(Product, product_id)
    if product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    product.stock = max(0, int(product.stock or 0) + int(amount))
    db.commit()
    db.refresh(product)
    return product.as_dict()


# ================================================================== orders ===
def _get_order(db: Session, order_id: int) -> Order:
    order = db.get(Order, order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    return order


@api.get(
    "/orders",
    tags=["orders"],
    response_model=list[OrderOut],
    dependencies=[Depends(security.require_user)],
)
def list_orders(
    db: Session = Depends(get_db),
    status: str | None = Query(default=None, description="PENDING | PAID | FAILED | CANCELLED"),
    payment_method: str | None = Query(default=None, description="CASH | KHQR"),
    search: str | None = Query(default=None, description="Order number / transaction id"),
    days: int | None = Query(default=None, ge=1, le=365),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    query = db.query(Order)
    if status:
        query = query.filter(Order.status == status.upper())
    if payment_method:
        query = query.filter(Order.payment_method == payment_method.upper())
    if search:
        like = f"%{search.strip()}%"
        query = query.filter(or_(Order.order_number.ilike(like), Order.transaction_id.ilike(like)))
    if days:
        since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
        query = query.filter(Order.created_at >= since)
    rows = query.order_by(Order.created_at.desc()).offset(offset).limit(limit).all()
    return [row.as_dict() for row in rows]


@api.get(
    "/orders/{order_id}",
    tags=["orders"],
    response_model=OrderOut,
    dependencies=[Depends(security.require_user)],
)
def get_order(order_id: int, db: Session = Depends(get_db)):
    return _get_order(db, order_id).as_dict()


@api.post(
    "/orders",
    tags=["orders"],
    response_model=OrderCreateResult,
    status_code=201,
    dependencies=[Depends(security.require_user)],
)
def create_order(payload: OrderCreate, db: Session = Depends(get_db)):
    """Create a sale.

    * ``payment_method = CASH`` -> settled instantly (cash received + change).
    * ``payment_method = KHQR`` -> order stored as PENDING and a signed KHQR is
      requested from ABA Payway (Direct QR API). The response carries the raw
      EMV string, the PNG url and the hosted checkout url as fallbacks.
    """
    order = crud.create_order(db, payload)

    if order.payment_method != "KHQR":
        return {"order": order.as_dict(), "payment_method": order.payment_method}

    if payload.success_url or payload.cancel_url:
        overrides = {}
        if payload.success_url:
            overrides["success_url"] = payload.success_url
        if payload.cancel_url:
            overrides["cancel_url"] = payload.cancel_url
        crud.save_settings(db, overrides)

    client = crud.get_client(db)
    result = crud.attach_qr_code(db, order, client)
    db.refresh(order)

    return {
        "order": order.as_dict(),
        "payment_method": order.payment_method,
        "qr_string": result["qr_string"],
        "qr_url": result["qr_url"],
        "checkout_url": result["checkout_url"],
        "gateway_ok": result["gateway_ok"],
        "gateway_message": result["gateway_message"],
    }


@api.post(
    "/orders/{order_id}/check-payment",
    tags=["orders"],
    response_model=PaymentCheckResult,
    dependencies=[Depends(security.require_user)],
)
def check_payment(order_id: int, db: Session = Depends(get_db)):
    """Poll ABA Payway ``check-transv2-khqrcc`` and settle the order on success."""
    order = _get_order(db, order_id)
    if order.payment_method != "KHQR":
        raise HTTPException(status_code=400, detail="This order is not a KHQR order")
    if order.status == "PAID":
        return {
            "order": order.as_dict(),
            "status": order.status,
            "paid": True,
            "gateway_status": "success",
            "gateway_message": "Already paid",
        }

    client = crud.get_client(db)
    if not client.configured:
        raise HTTPException(
            status_code=400,
            detail=(
                "ABA Payway is not configured. Add your Profile ID and Payment Secret in Settings."
            ),
        )

    try:
        result = client.check_transaction(order.transaction_id)
    except AbaPaywayError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    order.gateway_response = json.dumps(result.raw, ensure_ascii=False)[:8000]
    gateway_status = str(result.data.get("status", "") or "").lower()
    paid = bool(result.ok and gateway_status in ("success", "paid", "completed"))

    if paid:
        try:
            amount = float(result.data.get("amount")) if result.data.get("amount") else None
        except (TypeError, ValueError):
            amount = None
        crud.mark_paid(db, order, amount=amount, clear_error=True)
    else:
        if not result.ok:
            order.failure_reason = result.message
        db.commit()

    db.refresh(order)
    return {
        "order": order.as_dict(),
        "status": order.status,
        "paid": order.status == "PAID",
        "gateway_status": gateway_status or result.message,
        "gateway_message": result.message,
    }


@api.post(
    "/orders/{order_id}/mark-paid",
    tags=["orders"],
    response_model=OrderOut,
    dependencies=[Depends(security.require_admin)],
)
def mark_order_paid(
    order_id: int,
    amount: float | None = Query(default=None, ge=0),
    db: Session = Depends(get_db),
):
    """Manually settle a pending order (offline fallback).

    Only available while ``demo_mode`` is enabled in Settings.
    """
    settings = crud.get_settings(db)
    if str(settings.get("demo_mode", "true")).lower() not in ("1", "true", "yes", "on"):
        raise HTTPException(
            status_code=403,
            detail=(
                "Manual confirmation is disabled. Enable Demo mode in Settings or rely "
                "on the ABA webhook."
            ),
        )
    order = _get_order(db, order_id)
    if order.status == "PAID":
        return order.as_dict()
    crud.mark_paid(db, order, amount=amount, clear_error=True)
    db.refresh(order)
    return order.as_dict()


@api.post(
    "/orders/{order_id}/cancel",
    tags=["orders"],
    response_model=OrderOut,
    dependencies=[Depends(security.require_user)],
)
def cancel_order(order_id: int, db: Session = Depends(get_db)):
    order = _get_order(db, order_id)
    if order.status == "CANCELLED":
        return order.as_dict()
    if order.status == "PAID":
        raise HTTPException(status_code=400, detail="A paid order cannot be cancelled")
    order.status = "CANCELLED"
    db.commit()
    db.refresh(order)
    return order.as_dict()


# =========================================== ABA callback / webhook ==========
def _settle_from_gateway(db: Session, order: Order, amount_text: str | None, source: str) -> Order:
    amount = None
    if amount_text:
        try:
            amount = float(amount_text)
        except (TypeError, ValueError):
            amount = None
    crud.mark_paid(db, order, amount=amount, clear_error=True)
    db.refresh(order)
    return order


def _log_webhook(db: Session, payload: dict, valid: bool, source: str = "aba") -> None:
    db.add(
        WebhookLog(
            source=source,
            signature_valid=valid,
            payload=json.dumps(payload, ensure_ascii=False, default=str)[:8000],
        )
    )
    db.commit()


def _amount_mismatch(expected: float, amount_text: str | None) -> str | None:
    """Return a message when the gateway amount does not match the order total."""
    if not amount_text:
        return None
    try:
        paid = float(amount_text)
    except (TypeError, ValueError):
        return f"Unparsable amount '{amount_text}'"
    if abs(paid - float(expected or 0)) > 0.01:
        return f"Gateway reported {paid:.2f} but the order total is {float(expected or 0):.2f}"
    return None


async def _read_payload(request: Request) -> dict:
    """Accept JSON, form-encoded or query-string callbacks (gateways vary)."""
    payload: dict = {}
    try:
        body = await request.json()
        if isinstance(body, dict):
            payload.update(body)
    except Exception:
        try:
            form = await request.form()
            payload.update({k: str(v) for k, v in form.items()})
        except Exception:
            payload = {}
    payload.update({k: v for k, v in request.query_params.items() if k not in payload})
    return payload


@api.post("/webhook/aba", tags=["payments"])
async def aba_webhook(request: Request, db: Session = Depends(get_db)):
    """Server notification from ABA Payway.

    Signed POST (application/json) carrying ``transaction_id``, ``amount``,
    ``status`` and ``hash`` — verified with
    ``sha256(secret + req_time + transaction_id + amount + "SUCCESS")``.
    """
    payload = await _read_payload(request)
    client = crud.get_client(db)
    valid = client.verify_callback(payload)
    _log_webhook(db, payload, valid, source="aba-webhook")

    if not client.secret_key:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "detail": "Payment secret is not configured"},
        )
    if not valid:
        return JSONResponse(
            status_code=401,
            content={"ok": False, "detail": "Invalid signature"},
        )

    tx_id = (
        payload.get("transaction_id")
        or payload.get("transactionId")
        or payload.get("order_id")
    )
    order = db.query(Order).filter(Order.transaction_id == str(tx_id)).first()
    if order is None:
        return JSONResponse(
            status_code=404,
            content={"ok": False, "detail": f"No order found for transaction {tx_id}"},
        )

    amount_text = payload.get("amount") or payload.get("total") or payload.get("total_amount")
    _settle_from_gateway(db, order, amount_text, source="aba-webhook")
    return {
        "ok": True,
        "order_number": order.order_number,
        "status": order.status,
        "message": "Order settled",
    }


@api.get("/webhook/aba", tags=["payments"])
def aba_webhook_probe():
    """Health probe - some gateways GET the callback url before using it."""
    return {"ok": True, "message": "ABA webhook endpoint is reachable"}


@api.get("/payment/return", tags=["payments"])
def payment_return(request: Request, db: Session = Depends(get_db)):
    """Customer lands here after paying on the hosted ABA Pay checkout page.

    ABA appends ``success_hash``, ``success_time`` and ``success_amount`` to the
    ``success_url``. We verify them (when a secret is configured), settle the
    order and bounce the customer back to the POS UI.
    """
    params = dict(request.query_params)
    settings = crud.get_settings(db)
    frontend = (settings.get("frontend_base_url") or "http://localhost:3000").rstrip("/")

    tx_id = params.get("transaction_id") or params.get("transactionId")
    signoff = params.get("success_hash")
    req_time = params.get("success_time") or params.get("req_time")
    amount_text = params.get("success_amount") or params.get("amount")

    order = None
    if tx_id:
        order = db.query(Order).filter(Order.transaction_id == str(tx_id)).first()

    client = crud.get_client(db)
    verified = bool(
        client.verify_callback(
            {"req_time": req_time, "transaction_id": tx_id, "amount": amount_text}, signoff
        )
    )
    _log_webhook(db, params, verified, source="aba-redirect")

    if order is not None and verified:
        # SECURITY: only a signature-verified redirect may settle an order here.
        # Without a configured secret nothing can be verified, so the POS relies
        # on the signed webhook or on POST /api/orders/{id}/check-payment.
        mismatch = _amount_mismatch(order.total, amount_text)
        if mismatch:
            security.log_audit(
                db,
                action="payment-return amount mismatch",
                request=request,
                status_code=200,
                detail=f"{order.order_number}: {mismatch}",
            )
        _settle_from_gateway(db, order, amount_text, source="aba-redirect")
    elif order is not None:
        security.log_audit(
            db,
            action="payment-return rejected",
            request=request,
            status_code=200,
            detail=(
                f"{order.order_number}: redirect signature not verified"
                + ("" if client.secret_key else " (no Payment Secret configured)")
            ),
        )

    status = "success" if (order is not None and order.status == "PAID") else "pending"
    query = f"?payment={status}"
    if order is not None:
        query += f"&order={order.order_number}&order_id={order.id}"
    return RedirectResponse(url=f"{frontend}/{query}", status_code=302)


@api.get(
    "/webhook/logs",
    tags=["payments"],
    dependencies=[Depends(security.require_admin)],
)
def webhook_logs(limit: int = Query(default=50, ge=1, le=500), db: Session = Depends(get_db)):
    rows = (
        db.query(WebhookLog).order_by(WebhookLog.received_at.desc()).limit(limit).all()
    )
    return [row.as_dict() for row in rows]


# ================================================================ settings ===
@api.get("/settings", tags=["settings"], response_model=SettingsOut)
def read_settings(
    request: Request,
    user: User = Depends(security.require_user),
    db: Session = Depends(get_db),
):
    """Admins see every setting (secret masked); cashiers only the shop basics."""
    base = str(request.base_url).rstrip("/")
    if (user.role or "").lower() != "admin":
        return {"settings": crud.public_settings(db), "locked_keys": [], "webhook_url": None}
    return {
        "settings": crud.masked_settings(db),
        "locked_keys": sorted(env_locked_keys()),
        "webhook_url": f"{base}/api/webhook/aba",
    }


@api.put(
    "/settings",
    tags=["settings"],
    response_model=SettingsOut,
    dependencies=[Depends(security.require_admin)],
)
def update_settings(payload: SettingsUpdate, request: Request, db: Session = Depends(get_db)):
    data = payload.model_dump(exclude_unset=True)
    locked = env_locked_keys()
    blocked = sorted(set(data) & locked)
    if blocked:
        raise HTTPException(
            status_code=400,
            detail=(
                "These settings come from backend_api/.env and must be changed there: "
                + ", ".join(blocked)
            ),
        )
    # A masked value coming back from the UI means "leave it unchanged".
    secret = data.get("secret_key")
    if secret is not None and ("*" in str(secret) or str(secret).strip() == ""):
        data.pop("secret_key", None)

    if data.get("demo_mode") is not None:
        data["demo_mode"] = str(bool(data["demo_mode"])).lower()
    if data.get("amount_decimals") is not None:
        try:
            decimals = int(data["amount_decimals"])
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=400, detail="amount_decimals must be a number"
            ) from None
        if not 0 <= decimals <= 6:
            raise HTTPException(status_code=400, detail="amount_decimals must be between 0 and 6")
        data["amount_decimals"] = str(decimals)

    crud.save_settings(db, data)
    base = str(request.base_url).rstrip("/")
    return {
        "settings": crud.masked_settings(db),
        "locked_keys": sorted(locked),
        "webhook_url": f"{base}/api/webhook/aba",
    }


@api.get(
    "/settings/aba-urls",
    tags=["settings"],
    dependencies=[Depends(security.require_admin)],
)
def aba_urls(db: Session = Depends(get_db)):
    """Debug helper - shows every gateway endpoint this POS will call."""
    client = crud.get_client(db)
    settings = crud.get_settings(db)
    return {
        "configured": client.configured,
        "profile_id": client.profile_id,
        "api_base": client.api_base,
        "amount_decimals": client.decimals,
        "success_url": settings.get("success_url"),
        "cancel_url": settings.get("cancel_url"),
        "demo_mode": settings.get("demo_mode"),
        "endpoints": {
            "qr_checkout_redirect": client.checkout_get_url(),
            "qr_checkout_page": client.hosted_checkout_url(),
            "direct_qr_api": client.qr_api_url(),
            "check_transaction_v2": client.check_trans_url(),
        },
        "hash_formulas": {
            "checkout_and_qr": "sha1(secret + transaction_id + amount + success_url + remark)",
            "verify_v2": "sha1(secret + transaction_id)",
            "callback": 'sha256(secret + req_time + transaction_id + amount + "SUCCESS")',
        },
    }


# ============================================== backup / import / stats ======
@api.get(
    "/data/backup",
    tags=["data"],
    dependencies=[Depends(security.require_admin)],
)
def download_backup(db: Session = Depends(get_db)):
    """Download the complete POS dataset as one JSON file."""
    snapshot = crud.backup_data(db)
    filename = f"aba-pos-backup-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.json"
    return JSONResponse(
        content=snapshot,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@api.post(
    "/data/import",
    tags=["data"],
    dependencies=[Depends(security.require_admin)],
)
def upload_backup(payload: ImportRequest, db: Session = Depends(get_db)):
    """Import a JSON backup.

    ``mode = "merge"``   -> add what is missing, never touch existing rows
    ``mode = "replace"`` -> wipe products / categories / orders first
    """
    if not payload.data:
        raise HTTPException(status_code=400, detail="The uploaded file is empty")
    if payload.data.get("app") and payload.data.get("app") != "aba-pos":
        raise HTTPException(
            status_code=400,
            detail="This file was not produced by the ABA POS backup tool",
        )
    try:
        stats = crud.import_data(db, payload.data, payload.mode)
    except HTTPException:
        raise
    except Exception as exc:  # malformed file
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Import failed: {exc}") from exc
    return {"ok": True, "stats": stats}


@api.post(
    "/data/reset",
    tags=["data"],
    dependencies=[Depends(security.require_admin)],
)
def reset_data(
    confirm: str = Query(..., description="Type 'RESET' to confirm"),
    db: Session = Depends(get_db),
):
    """Delete every product, category and order (settings are kept)."""
    if confirm != "RESET":
        raise HTTPException(status_code=400, detail="Send confirm=RESET to proceed")
    crud._clear_transactional_tables(db)
    db.commit()
    return {"ok": True, "detail": "All products, categories and orders removed"}


@api.get(
    "/stats/summary",
    tags=["system"],
    dependencies=[Depends(security.require_user)],
)
def stats_summary(db: Session = Depends(get_db)):
    """Small dashboard payload for the POS header."""
    today = datetime.now(timezone.utc).replace(tzinfo=None).date()
    start = datetime.combine(today, datetime.min.time())
    end = datetime.combine(today, datetime.max.time())

    paid_today = (
        db.query(func.count(Order.id), func.coalesce(func.sum(Order.total), 0.0))
        .filter(Order.status == "PAID", Order.created_at.between(start, end))
        .one()
    )
    by_method = dict(
        db.query(Order.payment_method, func.coalesce(func.sum(Order.total), 0.0))
        .filter(Order.status == "PAID", Order.created_at.between(start, end))
        .group_by(Order.payment_method)
        .all()
    )
    pending = db.query(func.count(Order.id)).filter(Order.status == "PENDING").scalar() or 0

    return {
        "date": today.isoformat(),
        "orders_today": int(paid_today[0] or 0),
        "sales_today": money(paid_today[1] or 0),
        "cash_today": money(by_method.get("CASH", 0)),
        "khqr_today": money(by_method.get("KHQR", 0)),
        "pending_orders": int(pending),
        "products": db.query(func.count(Product.id)).scalar() or 0,
        "categories": db.query(func.count(Category.id)).scalar() or 0,
        "low_stock": db.query(func.count(Product.id)).filter(Product.stock <= 5).scalar() or 0,
    }


# ================================================================== auth =====
@api.post("/auth/login", tags=["auth"], response_model=LoginResult)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Exchange username + password for a bearer token (rate limited).

    The only public endpoint besides ``/health`` and the ABA webhook.
    """
    username = (payload.username or "").strip()
    request.state.audit_action = "login"

    if not security.login_allowed(request, username):
        wait = security.login_retry_after(request, username)
        request.state.audit_detail = f"locked out: username={username}"
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed sign-ins. Try again in {max(1, wait // 60)} minute(s).",
            headers={"Retry-After": str(max(1, wait))},
        )

    user = security.authenticate(db, username, payload.password)
    request.state.audit_always = True  # log successes as well as failures
    if user is None:
        request.state.audit_detail = f"failed sign-in: username={username}"
        raise HTTPException(status_code=401, detail="Wrong username or password.")

    security.login_succeeded(request, username)
    token, expires_at = security.issue_token(
        db,
        user,
        ttl_hours=TOKEN_TTL_HOURS,
        user_agent=request.headers.get("user-agent"),
        ip=security.client_ip(request),
    )
    request.state.user = user
    request.state.audit_detail = f"username={user.username} role={user.role}"
    return {"token": token, "expires_at": expires_at.isoformat(), "user": user.as_dict()}


@api.post("/auth/logout", tags=["auth"], response_model=Message)
def logout(
    request: Request,
    user: User = Depends(security.require_user),
    db: Session = Depends(get_db),
):
    """Drop the bearer token this request came in with."""
    request.state.audit_action = "logout"
    security.revoke_token(db, security.bearer_token(request))
    return {"detail": f"Signed out {user.username}"}


@api.post("/auth/logout-all", tags=["auth"], response_model=Message)
def logout_all(
    request: Request,
    user: User = Depends(security.require_user),
    db: Session = Depends(get_db),
):
    """Sign this account out on every device (e.g. after a phone went missing)."""
    request.state.audit_action = "logout-all"
    removed = security.revoke_tokens(db, user)
    return {"detail": f"Signed out {removed} session(s)."}


@api.get("/auth/me", tags=["auth"], response_model=UserOut)
def whoami(user: User = Depends(security.require_user)):
    """Who am I / what may I do - the POS uses this after a reload."""
    return user.as_dict()


@api.post("/auth/password", tags=["auth"], response_model=Message)
def change_own_password(
    payload: ChangePasswordRequest,
    request: Request,
    user: User = Depends(security.require_user),
    db: Session = Depends(get_db),
):
    """Change your own password; every other session is signed out."""
    request.state.audit_action = "password change"
    if not security.verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Your current password is not correct.")
    security.set_password(db, user, payload.new_password, revoke_sessions=False)
    security.revoke_tokens(db, user, keep=security.bearer_token(request))
    return {"detail": "Password updated. Other devices were signed out."}


# -------------------------------------- staff accounts (administrators only) --
@api.get(
    "/auth/users",
    tags=["auth"],
    response_model=list[UserOut],
    dependencies=[Depends(security.require_admin)],
)
def list_users(db: Session = Depends(get_db)):
    """Every POS account."""
    return [user.as_dict() for user in db.query(User).order_by(User.username).all()]


@api.post(
    "/auth/users",
    tags=["auth"],
    response_model=UserOut,
    status_code=201,
    dependencies=[Depends(security.require_admin)],
)
def create_staff(payload: UserCreateRequest, request: Request, db: Session = Depends(get_db)):
    """Add a cashier (or another administrator)."""
    request.state.audit_action = f"create user {payload.username}"
    user = security.create_user(
        db,
        username=payload.username,
        password=payload.password,
        role=payload.role,
        full_name=payload.full_name,
    )
    return user.as_dict()


@api.patch("/auth/users/{user_id}", tags=["auth"], response_model=UserOut)
def update_staff(
    user_id: int,
    payload: UserUpdateRequest,
    request: Request,
    admin: User = Depends(security.require_admin),
    db: Session = Depends(get_db),
):
    """Change a role, disable an account or reset a password."""
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    request.state.audit_action = f"update user {target.username}"

    if payload.role is not None and payload.role != target.role:
        if target.role == "admin":
            security.guard_last_admin(db, target, action="demote it")
        target.role = payload.role
    if payload.is_active is not None and bool(payload.is_active) != bool(target.is_active):
        if not payload.is_active:
            if target.id == admin.id:
                raise HTTPException(status_code=400, detail="You cannot disable your own account.")
            security.guard_last_admin(db, target, action="disable it")
        target.is_active = bool(payload.is_active)
        if not target.is_active:
            security.revoke_tokens(db, target)
    if payload.full_name is not None:
        target.full_name = payload.full_name.strip() or None
    if payload.password:
        security.set_password(db, target, payload.password)

    db.commit()
    db.refresh(target)
    return target.as_dict()


@api.delete("/auth/users/{user_id}", tags=["auth"], response_model=Message)
def delete_staff(
    user_id: int,
    request: Request,
    admin: User = Depends(security.require_admin),
    db: Session = Depends(get_db),
):
    """Remove an account (never yourself, never the last administrator)."""
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")
    security.guard_last_admin(db, target, action="delete it")
    request.state.audit_action = f"delete user {target.username}"
    security.revoke_tokens(db, target)
    username = target.username
    db.delete(target)
    db.commit()
    return {"detail": f"'{username}' deleted"}


@api.get("/auth/audit", tags=["auth"], response_model=list[AuditOut])
def audit_trail(
    limit: int = Query(default=100, ge=1, le=1000),
    admin: User = Depends(security.require_admin),
    db: Session = Depends(get_db),
):
    """Newest-first trail of everything that was created, changed or rejected."""
    rows = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(limit).all()
    return [row.as_dict() for row in rows]


app.include_router(api)


@app.exception_handler(AbaPaywayError)
async def aba_error_handler(_request: Request, exc: AbaPaywayError):
    return JSONResponse(status_code=502, content={"detail": str(exc)})


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
