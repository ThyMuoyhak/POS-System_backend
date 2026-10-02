"""ORM models for the POS."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def money(value) -> float:
    """Round a value to 2 decimals to keep float noise out of the database."""
    return float(Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


class Category(Base):
    __tablename__ = "categories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    color: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    products: Mapped[list["Product"]] = relationship(back_populates="category")

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "color": self.color,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

class Product(Base):
    __tablename__ = "products"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    image_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    sku: Mapped[str | None] = mapped_column(String(64), nullable=True)
    price: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    # discount is a PERCENTAGE (0 - 100). 10 == 10% off.
    discount: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    stock: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    category_id: Mapped[int | None] = mapped_column(
        ForeignKey("categories.id", ondelete="SET NULL"), nullable=True, index=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    category: Mapped["Category | None"] = relationship(back_populates="products")

    @property
    def final_price(self) -> float:
        """Price the customer actually pays after the percentage discount."""
        return money(self.price * (1 - (self.discount or 0) / 100))

    @property
    def in_stock(self) -> bool:
        return (self.stock or 0) > 0

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "image_url": self.image_url,
            "sku": self.sku,
            "price": money(self.price),
            "discount": round(self.discount or 0, 2),
            "final_price": self.final_price,
            "stock": self.stock,
            "in_stock": self.in_stock,
            "is_active": self.is_active,
            "category_id": self.category_id,
            "category_name": self.category.name if self.category else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class Order(Base):
    __tablename__ = "orders"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    order_number: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    # transaction_id sent to ABA Payway (defaults to order_number)
    transaction_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    payment_method: Mapped[str] = mapped_column(String(16), nullable=False, default="CASH")  # CASH | KHQR
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING", index=True)

    subtotal: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    discount_total: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    total: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    amount_paid: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    change_amount: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    currency: Mapped[str] = mapped_column(String(8), nullable=False, default="USD")

    customer_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    qr_string: Mapped[str | None] = mapped_column(Text, nullable=True)
    qr_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    checkout_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    gateway_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    paid_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    items: Mapped[list["OrderItem"]] = relationship(
        back_populates="order", cascade="all, delete-orphan", lazy="selectin"
    )

    def as_dict(self, with_items: bool = True) -> dict:
        data = {
            "id": self.id,
            "order_number": self.order_number,
            "transaction_id": self.transaction_id,
            "payment_method": self.payment_method,
            "status": self.status,
            "subtotal": money(self.subtotal),
            "discount_total": money(self.discount_total),
            "total": money(self.total),
            "amount_paid": money(self.amount_paid),
            "change_amount": money(self.change_amount),
            "currency": self.currency,
            "customer_note": self.customer_note,
            "qr_string": self.qr_string,
            "qr_url": self.qr_url,
            "checkout_url": self.checkout_url,
            "failure_reason": self.failure_reason,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "paid_at": self.paid_at.isoformat() if self.paid_at else None,
            "item_count": len(self.items or []),
        }
        if with_items:
            data["items"] = [item.as_dict() for item in (self.items or [])]
        return data


class OrderItem(Base):
    __tablename__ = "order_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    order_id: Mapped[int] = mapped_column(ForeignKey("orders.id", ondelete="CASCADE"), nullable=False)
    product_id: Mapped[int | None] = mapped_column(
        ForeignKey("products.id", ondelete="SET NULL"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    image_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    unit_price: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    discount: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)  # percent
    quantity: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    line_total: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    order: Mapped["Order"] = relationship(back_populates="items")

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "product_id": self.product_id,
            "title": self.title,
            "image_url": self.image_url,
            "unit_price": money(self.unit_price),
            "discount": round(self.discount or 0, 2),
            "quantity": self.quantity,
            "line_total": money(self.line_total),
        }


class User(Base):
    """POS operator account.

    ``admin``   -> everything (catalogue, settings, users, backups)
    ``cashier`` -> sell only (browse the catalogue, create/refund orders)
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    full_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="cashier", index=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "full_name": self.full_name,
            "role": self.role,
            "is_active": bool(self.is_active),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
        }


class AuthToken(Base):
    """A login session.

    Only the SHA-256 of the bearer token is stored, so a copy of ``pos.db``
    never hands somebody a working session.
    """

    __tablename__ = "auth_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    created_at: Mapped[int] = mapped_column(Integer, nullable=False, default=lambda: int(time.time()))
    expires_at: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    last_used_at: Mapped[int | None] = mapped_column(Integer, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(200), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)


class AuditLog(Base):
    """Append-only trail: who created / changed / deleted what, and when."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[int] = mapped_column(Integer, nullable=False, default=lambda: int(time.time()), index=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    role: Mapped[str | None] = mapped_column(String(16), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    method: Mapped[str | None] = mapped_column(String(8), nullable=True)
    path: Mapped[str | None] = mapped_column(String(200), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str | None] = mapped_column(String(60), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "at": self.at,
            "at_iso": datetime.fromtimestamp(self.at, timezone.utc).isoformat() if self.at else None,
            "user_id": self.user_id,
            "username": self.username,
            "role": self.role,
            "ip": self.ip,
            "method": self.method,
            "path": self.path,
            "status_code": self.status_code,
            "action": self.action,
            "detail": self.detail,
        }


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)

    def as_dict(self) -> dict:
        return {"key": self.key, "value": self.value}


class WebhookLog(Base):
    """Raw record of every callback received from ABA Payway (audit trail)."""

    __tablename__ = "webhook_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="aba")
    signature_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "received_at": self.received_at.isoformat() if self.received_at else None,
            "source": self.source,
            "signature_valid": self.signature_valid,
            "payload": self.payload,
        }

