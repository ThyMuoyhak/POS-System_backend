"""Pydantic request / response models."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

PaymentMethod = Literal["CASH", "KHQR"]
OrderStatus = Literal["PENDING", "PAID", "FAILED", "CANCELLED"]


# --------------------------------------------------------------------- category
class CategoryBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: str | None = None
    color: str | None = None


class CategoryCreate(CategoryBase):
    pass


class CategoryUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = None
    color: str | None = None


class CategoryOut(CategoryBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: str | None = None
    product_count: int = 0


# ---------------------------------------------------------------------- product
class ProductBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: str | None = None
    image_url: str | None = None
    sku: str | None = None
    price: float = Field(default=0.0, ge=0)
    discount: float = Field(default=0.0, ge=0, le=100, description="Discount percentage 0-100")
    stock: int = Field(default=0, ge=0)
    category_id: int | None = None
    is_active: bool = True


class ProductCreate(ProductBase):
    pass


class ProductUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    image_url: str | None = None
    sku: str | None = None
    price: float | None = Field(default=None, ge=0)
    discount: float | None = Field(default=None, ge=0, le=100)
    stock: int | None = Field(default=None, ge=0)
    category_id: int | None = None
    is_active: bool | None = None


class ProductOut(ProductBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    final_price: float = 0.0
    in_stock: bool = False
    category_name: str | None = None
    created_at: str | None = None
    updated_at: str | None = None


# ------------------------------------------------------------------------ order
class OrderItemIn(BaseModel):
    product_id: int
    quantity: int = Field(default=1, ge=1)
    # Optional per-line discount override (percentage). Falls back to the
    # product's own discount when omitted.
    discount: float | None = Field(default=None, ge=0, le=100)


class OrderCreate(BaseModel):
    payment_method: PaymentMethod = "CASH"
    items: list[OrderItemIn] = Field(..., min_length=1)
    customer_note: str | None = None
    # CASH only
    amount_paid: float | None = Field(default=None, ge=0)
    # KHQR only - override the URLs configured in Settings
    success_url: str | None = None
    cancel_url: str | None = None

    @field_validator("items")
    @classmethod
    def _unique_products(cls, items: list[OrderItemIn]) -> list[OrderItemIn]:
        seen: set[int] = set()
        for item in items:
            if item.product_id in seen:
                raise ValueError(f"Duplicate product_id {item.product_id} in cart")
            seen.add(item.product_id)
        return items


class OrderItemOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    product_id: int | None = None
    title: str
    image_url: str | None = None
    unit_price: float
    discount: float
    quantity: int
    line_total: float


class OrderOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    order_number: str
    transaction_id: str
    payment_method: str
    status: str
    subtotal: float
    discount_total: float
    total: float
    amount_paid: float
    change_amount: float
    currency: str
    customer_note: str | None = None
    qr_string: str | None = None
    qr_url: str | None = None
    checkout_url: str | None = None
    failure_reason: str | None = None
    created_at: str | None = None
    paid_at: str | None = None
    item_count: int = 0
    items: list[OrderItemOut] = []


class OrderCreateResult(BaseModel):
    """Returned by POST /api/orders - the order plus what the POS needs next."""

    order: OrderOut
    payment_method: str
    # KHQR helpers
    qr_string: str | None = None
    qr_url: str | None = None
    checkout_url: str | None = None
    gateway_ok: bool = True
    gateway_message: str | None = None


class PaymentCheckResult(BaseModel):
    order: OrderOut
    status: str
    paid: bool
    gateway_status: str | None = None
    gateway_message: str | None = None


# --------------------------------------------------------------------- settings
class SettingsOut(BaseModel):
    settings: dict[str, str]
    locked_keys: list[str] = []
    webhook_url: str | None = None


class SettingsUpdate(BaseModel):
    merchant_name: str | None = None
    currency: str | None = None
    profile_id: str | None = None
    secret_key: str | None = None
    api_base: str | None = None
    success_url: str | None = None
    cancel_url: str | None = None
    frontend_base_url: str | None = None
    demo_mode: Any = None
    amount_decimals: Any = None


# ------------------------------------------------------------------------- data
class ImportRequest(BaseModel):
    data: dict[str, Any]
    mode: Literal["merge", "replace"] = "merge"


# ------------------------------------------------------------------------ auth
Role = Literal["admin", "cashier"]


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=200)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    full_name: str | None = None
    role: str
    is_active: bool = True
    created_at: str | None = None
    last_login_at: str | None = None


class LoginResult(BaseModel):
    """Bearer token the POS UI stores and sends back in the Authorization header."""

    token: str
    expires_at: str
    user: UserOut


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=200)
    new_password: str = Field(..., min_length=1, max_length=200)


class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=1, max_length=200)
    role: Role = "cashier"
    full_name: str | None = Field(default=None, max_length=120)


class UserUpdateRequest(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    full_name: str | None = Field(default=None, max_length=120)
    password: str | None = Field(default=None, max_length=200)


class AuditOut(BaseModel):
    id: int
    at: int
    at_iso: str | None = None
    user_id: int | None = None
    username: str | None = None
    role: str | None = None
    ip: str | None = None
    method: str | None = None
    path: str | None = None
    status_code: int | None = None
    action: str | None = None
    detail: str | None = None


# ------------------------------------------------------------------------ misc
class Message(BaseModel):
    detail: str
