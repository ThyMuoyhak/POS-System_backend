"""Business logic: settings, orders, stock, backup & import."""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from aba_payway import AbaPaywayClient
from config import get_settings_snapshot
from models import Category, Order, OrderItem, Product, Setting, money, utcnow
from schemas import OrderCreate

BACKUP_VERSION = 1
ORDER_PREFIX = "POS"


# ------------------------------------------------------------------- settings
def get_settings_dict(db: Session) -> dict[str, str]:
    rows = db.query(Setting).all()
    return {row.key: (row.value if row.value is not None else "") for row in rows}


def get_settings(db: Session) -> dict[str, str]:
    """Fully merged settings (defaults <- database <- environment)."""
    return get_settings_snapshot(get_settings_dict(db))


def save_settings(db: Session, values: dict) -> dict[str, str]:
    for key, value in values.items():
        if value is None:
            continue
        row = db.get(Setting, key)
        text = str(value)
        if row is None:
            db.add(Setting(key=key, value=text))
        else:
            row.value = text
    db.commit()
    return get_settings(db)


def get_client(db: Session) -> AbaPaywayClient:
    settings = get_settings(db)
    try:
        decimals = int(settings.get("amount_decimals", "2") or 2)
    except (TypeError, ValueError):
        decimals = 2
    return AbaPaywayClient(
        api_base=settings.get("api_base", ""),
        profile_id=settings.get("profile_id", ""),
        secret_key=settings.get("secret_key", ""),
        decimals=decimals,
    )


def masked_settings(db: Session) -> dict[str, str]:
    """Settings for the UI - the payment secret is masked."""
    settings = get_settings(db)
    out: dict[str, str] = {}
    for key, value in settings.items():
        if key == "secret_key":
            if value:
                out[key] = f"{'*' * max(len(value) - 4, 4)}{value[-4:]}"
                out["secret_key_set"] = "true"
            else:
                out[key] = ""
                out["secret_key_set"] = "false"
        else:
            out[key] = value
    return out


# Settings a cashier may see: no merchant ids, no gateway urls, no secret.
PUBLIC_SETTING_KEYS = ("merchant_name", "currency", "demo_mode", "amount_decimals")


def public_settings(db: Session) -> dict[str, str]:
    settings = get_settings(db)
    return {key: settings[key] for key in PUBLIC_SETTING_KEYS if key in settings}


# -------------------------------------------------------------------- helpers
def _new_order_number(db: Session) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    for _ in range(20):
        candidate = f"{ORDER_PREFIX}-{stamp}-{secrets.randbelow(900000) + 100000}"
        if not db.query(Order.id).filter(Order.order_number == candidate).first():
            return candidate
    return f"{ORDER_PREFIX}-{stamp}-{secrets.token_hex(4).upper()}"


def _new_transaction_id(db: Session, order_number: str) -> str:
    """ABA accepts A-Z 0-9 _ only - keep it short and unique."""
    base = order_number.replace("-", "")
    for suffix in range(100):
        candidate = base if suffix == 0 else f"{base}{suffix}"
        if not db.query(Order.id).filter(Order.transaction_id == candidate).first():
            return candidate
    return f"{base}{secrets.token_hex(3).upper()}"


def deduct_stock(db: Session, order: Order) -> None:
    """Take the sold quantities out of stock (never below zero)."""
    for item in order.items:
        if not item.product_id:
            continue
        product = db.get(Product, item.product_id)
        if product is None:
            continue
        product.stock = max(0, int(product.stock or 0) - int(item.quantity or 0))


def restore_stock(db: Session, order: Order) -> None:
    """Put the quantities back (used when an order is cancelled)."""
    for item in order.items:
        if not item.product_id:
            continue
        product = db.get(Product, item.product_id)
        if product is None:
            continue
        product.stock = int(product.stock or 0) + int(item.quantity or 0)


# --------------------------------------------------------------------- orders
def _cart_lines(db: Session, payload: OrderCreate):
    """Validate the cart against live stock and compute every money column."""
    lines = []
    subtotal = 0.0
    discount_total = 0.0
    for line in payload.items:
        product = db.get(Product, line.product_id)
        if product is None:
            raise HTTPException(status_code=404, detail=f"Product {line.product_id} not found")
        if not product.is_active:
            raise HTTPException(status_code=400, detail=f"'{product.title}' is not available")
        if int(product.stock or 0) < int(line.quantity):
            raise HTTPException(
                status_code=400,
                detail=f"Not enough stock for '{product.title}' ({int(product.stock or 0)} left)",
            )
        discount = product.discount or 0.0
        if line.discount is not None:
            discount = line.discount
        gross = money(product.price * line.quantity)
        net = money(product.price * (1 - discount / 100) * line.quantity)
        subtotal += gross
        discount_total += gross - net
        lines.append((product, discount, net, line.quantity))
    return lines, money(subtotal), money(discount_total)


def create_order(db: Session, payload: OrderCreate) -> Order:
    """Create an order. CASH is settled immediately, KHQR stays PENDING."""
    settings = get_settings(db)
    currency = settings.get("currency", "USD") or "USD"
    lines, subtotal, discount_total = _cart_lines(db, payload)
    total = money(subtotal - discount_total)

    order = Order(
        order_number=_new_order_number(db),
        transaction_id="",
        payment_method=payload.payment_method,
        status="PENDING",
        subtotal=subtotal,
        discount_total=discount_total,
        total=total,
        currency=currency,
        customer_note=payload.customer_note,
    )
    order.transaction_id = _new_transaction_id(db, order.order_number)

    for product, discount, net, quantity in lines:
        order.items.append(
            OrderItem(
                product_id=product.id,
                title=product.title,
                image_url=product.image_url,
                unit_price=money(product.price),
                discount=round(discount, 2),
                quantity=quantity,
                line_total=net,
            )
        )

    db.add(order)
    db.flush()  # assigns order.id to the items

    if payload.payment_method == "CASH":
        paid = payload.amount_paid if payload.amount_paid is not None else total
        if paid + 0.0001 < total:
            db.rollback()
            raise HTTPException(
                status_code=400,
                detail=f"Cash received ({money(paid):.2f}) is less than the total ({total:.2f})",
            )
        order.amount_paid = money(paid)
        order.change_amount = money(max(0.0, paid - total))
        order.status = "PAID"
        order.paid_at = utcnow()
        deduct_stock(db, order)

    db.commit()
    db.refresh(order)
    return order


def attach_qr_code(db: Session, order: Order, client: AbaPaywayClient) -> dict:
    """Call the headless Direct QR API and store the KHQR on the order.

    Returns a small dict so the POS UI can react: ``gateway_ok=False`` plus a
    ``gateway_message`` explains what to fall back to (the hosted checkout page).
    """
    settings = get_settings(db)
    success_url = settings.get("success_url") or "http://localhost:3000/?payment=success"
    cancel_url = settings.get("cancel_url") or ""
    remark = order.customer_note or f"Order {order.order_number}"
    items_text = f"{order.order_number}|{len(order.items)} items"

    order.checkout_url = client.build_checkout_url(
        transaction_id=order.transaction_id,
        amount=order.total,
        success_url=success_url,
        remark=remark,
        cancel_url=cancel_url or None,
        items=items_text,
    )

    if not client.configured:
        order.failure_reason = (
            "ABA Payway credentials are not configured yet - open Settings and add "
            "your Profile ID and Payment Secret."
        )
        db.commit()
        return _qr_payload(order, False, order.failure_reason)

    try:
        result = client.create_qr(
            transaction_id=order.transaction_id,
            amount=order.total,
            success_url=success_url,
            remark=remark,
            cancel_url=cancel_url or None,
            items=items_text,
        )
    except Exception as exc:  # AbaPaywayError or anything unexpected
        order.failure_reason = str(exc)
        db.commit()
        return _qr_payload(order, False, str(exc))

    order.gateway_response = json.dumps(result.raw, ensure_ascii=False)[:8000]
    qr_string = result.data.get("qr") or result.data.get("qr_string") or result.data.get("qrcode")
    qr_url = (
        result.data.get("qr_url")
        or result.data.get("qr_image")
        or result.data.get("image_url")
    )
    if result.ok and qr_string:
        order.qr_string = qr_string
        order.qr_url = qr_url
        order.failure_reason = None
        db.commit()
        return _qr_payload(order, True, result.message)

    order.failure_reason = result.message or "ABA Payway did not return a QR code"
    db.commit()
    return _qr_payload(order, False, order.failure_reason)


def _qr_payload(order: Order, ok: bool, message: str | None) -> dict:
    return {
        "gateway_ok": ok,
        "gateway_message": message,
        "qr_string": order.qr_string,
        "qr_url": order.qr_url,
        "checkout_url": order.checkout_url,
    }


def mark_paid(
    db: Session, order: Order, amount: float | None = None, clear_error: bool = False
) -> Order:
    """Settle an order exactly once (stock is only deducted on the first call)."""
    if order.status == "PAID":
        return order
    order.status = "PAID"
    order.paid_at = utcnow()
    order.amount_paid = money(amount if amount is not None else order.total)
    order.change_amount = 0.0
    if clear_error:
        order.failure_reason = None
    deduct_stock(db, order)
    db.commit()
    db.refresh(order)
    return order


# ------------------------------------------------------------- backup / import
def backup_data(db: Session) -> dict:
    """Full snapshot of the POS database - everything the importer understands."""
    categories = db.query(Category).order_by(Category.id).all()
    products = db.query(Product).order_by(Product.id).all()
    orders = db.query(Order).order_by(Order.id).all()
    settings = get_settings_dict(db)

    order_rows = []
    for order in orders:
        row = order.as_dict(with_items=False)
        row["items"] = [
            {
                "product_id": item.product_id,
                "title": item.title,
                "image_url": item.image_url,
                "unit_price": item.unit_price,
                "discount": item.discount,
                "quantity": item.quantity,
                "line_total": item.line_total,
            }
            for item in (order.items or [])
        ]
        order_rows.append(row)

    return {
        "app": "aba-pos",
        "version": BACKUP_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "settings": settings,
        "categories": [c.as_dict() for c in categories],
        "products": [p.as_dict() for p in products],
        "orders": order_rows,
        "counts": {
            "categories": len(categories),
            "products": len(products),
            "orders": len(order_rows),
            "order_items": sum(len(o["items"]) for o in order_rows),
        },
    }


def _clear_transactional_tables(db: Session) -> None:
    """Wipe catalogue + sales data (settings survive)."""
    for item in db.query(OrderItem).all():
        db.delete(item)
    for order in db.query(Order).all():
        db.delete(order)
    for product in db.query(Product).all():
        db.delete(product)
    for category in db.query(Category).all():
        db.delete(category)
    db.flush()


def import_data(db: Session, payload: dict, mode: str = "merge") -> dict:
    """Restore a snapshot produced by :func:`backup_data`.

    ``replace`` wipes categories / products / orders first. ``merge`` matches by
    category name, product sku/title and order number and only adds what is new.
    """
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Backup payload must be a JSON object")

    categories = payload.get("categories") or []
    products = payload.get("products") or []
    orders = payload.get("orders") or []
    settings = payload.get("settings") or {}
    stats = {
        "mode": mode,
        "categories_created": 0,
        "categories_matched": 0,
        "products_created": 0,
        "products_updated": 0,
        "orders_created": 0,
        "orders_skipped": 0,
        "settings_applied": 0,
    }

    if mode == "replace":
        _clear_transactional_tables(db)

    # --- categories (match by lowercase name) -----------------------------
    cat_by_id: dict[int, "Category"] = {}
    cat_by_name = {(c.name or "").strip().lower(): c for c in db.query(Category).all()}
    for row in categories:
        name = (row.get("name") or "").strip()
        if not name:
            continue
        existing = cat_by_name.get(name.lower())
        if existing is not None:
            stats["categories_matched"] += 1
        else:
            existing = Category(
                name=name, description=row.get("description"), color=row.get("color")
            )
            db.add(existing)
            db.flush()
            cat_by_name[name.lower()] = existing
            stats["categories_created"] += 1
        if row.get("id") is not None:
            cat_by_id[int(row["id"])] = existing

    # --- products (match by sku, then by exact title) ---------------------
    prod_by_id: dict[int, "Product"] = {}
    existing_products = db.query(Product).all()
    prod_by_sku = {p.sku: p for p in existing_products if p.sku}
    prod_by_title = {(p.title or "").strip().lower(): p for p in existing_products}
    for row in products:
        title = (row.get("title") or "").strip()
        if not title:
            continue
        sku = (row.get("sku") or "").strip() or None
        product = prod_by_sku.get(sku) if sku else None
        if product is None:
            product = prod_by_title.get(title.lower())

        if product is None:
            product = Product(title=title)
            db.add(product)
            stats["products_created"] += 1
        else:
            stats["products_updated"] += 1

        product.title = title
        product.description = row.get("description")
        product.image_url = row.get("image_url")
        product.sku = sku
        product.price = float(row.get("price") or 0)
        product.discount = float(row.get("discount") or 0)
        product.stock = int(row.get("stock") or 0)
        product.is_active = bool(row.get("is_active", True))
        raw_category = row.get("category_id")
        category = cat_by_id.get(int(raw_category)) if raw_category else None
        product.category_id = category.id if category else None
        db.flush()
        if sku:
            prod_by_sku[sku] = product
        prod_by_title[title.lower()] = product
        if row.get("id") is not None:
            prod_by_id[int(row["id"])] = product

    stats.update(_import_orders(db, orders, prod_by_id))
    stats["settings_applied"] = _import_settings(db, settings, mode)

    db.commit()
    return stats


def _import_orders(db: Session, orders: list, prod_by_id: dict) -> dict:
    created = 0
    skipped = 0
    for row in orders:
        order_number = (row.get("order_number") or "").strip()
        if not order_number:
            skipped += 1
            continue
        transaction_id = (row.get("transaction_id") or "").strip() or order_number
        clash = (
            db.query(Order.id)
            .filter((Order.order_number == order_number) | (Order.transaction_id == transaction_id))
            .first()
        )
        if clash:
            skipped += 1
            continue

        order = Order(
            order_number=order_number,
            transaction_id=transaction_id,
            payment_method=row.get("payment_method", "CASH"),
            status=row.get("status", "PAID"),
            subtotal=float(row.get("subtotal") or 0),
            discount_total=float(row.get("discount_total") or 0),
            total=float(row.get("total") or 0),
            amount_paid=float(row.get("amount_paid") or 0),
            change_amount=float(row.get("change_amount") or 0),
            currency=row.get("currency", "USD"),
            customer_note=row.get("customer_note"),
            qr_string=row.get("qr_string"),
            qr_url=row.get("qr_url"),
            checkout_url=row.get("checkout_url"),
        )
        order.created_at = _parse_dt(row.get("created_at")) or utcnow()
        order.paid_at = _parse_dt(row.get("paid_at"))
        for item in row.get("items") or []:
            raw_pid = item.get("product_id")
            mapped = prod_by_id.get(int(raw_pid)) if raw_pid else None
            order.items.append(
                OrderItem(
                    product_id=mapped.id if mapped else None,
                    title=item.get("title") or "Item",
                    image_url=item.get("image_url"),
                    unit_price=float(item.get("unit_price") or 0),
                    discount=float(item.get("discount") or 0),
                    quantity=int(item.get("quantity") or 1),
                    line_total=float(item.get("line_total") or 0),
                )
            )
        db.add(order)
        db.flush()
        created += 1
    return {"orders_created": created, "orders_skipped": skipped}


def _import_settings(db: Session, settings: dict, mode: str) -> int:
    """replace -> apply everything, merge -> only fill in missing keys."""
    if not settings:
        return 0
    if mode == "replace":
        save_settings(db, settings)
        return len(settings)
    current = get_settings_dict(db)
    missing = {k: v for k, v in settings.items() if k not in current}
    if missing:
        save_settings(db, missing)
    return len(missing)


def _parse_dt(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# ------------------------------------------------------------------- seeding
DEMO_CATALOG = [
    (
        "Coffee & Drinks",
        "#f97316",
        [
            ("Iced Latte", "Double shot espresso, fresh milk, ice.", 3.50, 0, 42,
             "https://images.unsplash.com/photo-1461023058943-07fcbe16d735?w=600"),
            ("Cappuccino", "Espresso with steamed milk foam.", 3.00, 10, 35,
             "https://images.unsplash.com/photo-1572442388796-11668a67e53d?w=600"),
            ("Matcha Latte", "Ceremonial grade matcha with oat milk.", 4.25, 0, 20,
             "https://images.unsplash.com/photo-1536013455962-2d59b3ba7a19?w=600"),
        ],
    ),
    (
        "Bakery",
        "#eab308",
        [
            ("Butter Croissant", "Flaky 24-layer French butter croissant.", 2.20, 0, 25,
             "https://images.unsplash.com/photo-1555507036-ab1f4038808a?w=600"),
            ("Blueberry Muffin", "Baked daily with wild blueberries.", 2.75, 15, 18,
             "https://images.unsplash.com/photo-1607958996333-41aef7caefaa?w=600"),
        ],
    ),
    (
        "Merch",
        "#6366f1",
        [
            ("Ceramic Mug", "350ml stoneware mug with logo.", 9.90, 20, 12,
             "https://images.unsplash.com/photo-1514228742587-6b1558fcca3d?w=600"),
            ("Reusable Tumbler", "Insulated 500ml stainless steel tumbler.", 15.00, 0, 8,
             "https://images.unsplash.com/photo-1523362628745-0c100150b504?w=600"),
        ],
    ),
]


def seed_demo_data(db: Session) -> bool:
    """Populate a small demo catalogue the first time the POS starts."""
    if db.query(Product.id).first() is not None:
        return False
    for name, color, items in DEMO_CATALOG:
        category = Category(name=name, color=color, description=f"{name} category")
        db.add(category)
        db.flush()
        for title, description, price, discount, stock, image_url in items:
            db.add(
                Product(
                    title=title,
                    description=description,
                    image_url=image_url,
                    price=price,
                    discount=discount,
                    stock=stock,
                    category_id=category.id,
                )
            )
    db.commit()
    return True
