"""Temporary end-to-end security test - runs against a throwaway database."""
import os
import pathlib

TEST_DB = pathlib.Path(__file__).with_name("_security_test.db")
if TEST_DB.exists():
    TEST_DB.unlink()
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["POS_ADMIN_PASSWORD"] = "TestAdminPass123"
# The real ABA credentials live in backend_api/.env; give the test its own so
# it never depends on (or writes to) the developer's live configuration.
os.environ["ABA_PROFILE_ID"] = "selftest-profile"
os.environ["ABA_SECRET_KEY"] = "selftest-secret-key"
os.environ.pop("POS_AUTH_DISABLED", None)
os.environ.pop("POS_ENABLE_DOCS", None)

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402

FAILED = []


def check(name, ok, extra=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   [{extra}]" if extra else ""))
    if not ok:
        FAILED.append(name)


PROTECTED = [
    ("get", "/api/products"),
    ("get", "/api/products/1"),
    ("get", "/api/categories"),
    ("get", "/api/orders"),
    ("get", "/api/orders/1"),
    ("get", "/api/stats/summary"),
    ("get", "/api/settings"),
    ("get", "/api/settings/aba-urls"),
    ("get", "/api/webhook/logs"),
    ("get", "/api/data/backup"),
    ("get", "/api/auth/users"),
    ("get", "/api/auth/audit"),
    ("get", "/api/auth/me"),
    ("post", "/api/orders"),
    ("post", "/api/orders/1/cancel"),
    ("post", "/api/orders/1/check-payment"),
    ("post", "/api/orders/1/mark-paid"),
    ("post", "/api/products"),
    ("post", "/api/categories"),
    ("put", "/api/settings"),
    ("post", "/api/data/import"),
    ("post", "/api/data/reset?confirm=RESET"),
    ("post", "/api/auth/users"),
    ("patch", "/api/auth/users/1"),
    ("delete", "/api/auth/users/1"),
]

CASHIER_DENIED = [
    ("post", "/api/products", {"title": "sneaky", "price": 1}),
    ("put", "/api/products/{pid}", {"price": 999}),
    ("delete", "/api/products/{pid}", None),
    ("post", "/api/products/{pid}/stock?amount=5", None),
    ("post", "/api/categories", {"name": "sneaky"}),
    ("put", "/api/settings", {"merchant_name": "hacked"}),
    ("post", "/api/data/import", {"data": {}, "mode": "merge"}),
    ("post", "/api/data/reset?confirm=RESET", None),
    ("get", "/api/data/backup", None),
    ("get", "/api/webhook/logs", None),
    ("get", "/api/settings/aba-urls", None),
    ("get", "/api/auth/users", None),
    ("get", "/api/auth/audit", None),
]


def run(client):
    check("GET /api/health stays public", client.get("/api/health").status_code == 200)

    blocked = 0
    for method, path in PROTECTED:
        kwargs = {"json": {}} if method in ("post", "put", "patch") else {}
        response = getattr(client, method)(path, **kwargs)
        if response.status_code == 401:
            blocked += 1
        else:
            print(f"      -> {method.upper()} {path} returned {response.status_code}: {response.text[:120]}")
    check("every protected route rejects anonymous calls", blocked == len(PROTECTED),
          f"{blocked}/{len(PROTECTED)} returned 401")

    check("interactive docs are gone", client.get("/docs").status_code == 404)
    check("openapi.json is gone", client.get("/openapi.json").status_code == 404)
    check("redoc is gone", client.get("/redoc").status_code == 404)

    health = client.get("/api/health")
    check("security headers on responses",
          health.headers.get("x-frame-options") == "DENY"
          and health.headers.get("x-content-type-options") == "nosniff"
          and health.headers.get("referrer-policy") == "no-referrer",
          str(dict(health.headers))[:200])
    check("API responses are not cached", health.headers.get("cache-control") == "no-store")

    check("wrong password is rejected",
          client.post("/api/auth/login", json={"username": "admin", "password": "nope"}).status_code == 401)
    response = client.post("/api/auth/login", json={"username": "admin", "password": "TestAdminPass123"})
    check("administrator can sign in", response.status_code == 200, response.text[:160])
    admin = {"Authorization": f"Bearer {response.json()['token']}"}
    check("login returns the role", response.json()["user"]["role"] == "admin")

    # --- administrator capabilities ----------------------------------------
    check("admin reads products", client.get("/api/products", headers=admin).status_code == 200)
    response = client.post("/api/products", json={"title": "SecTest Widget", "price": 5, "stock": 3}, headers=admin)
    check("admin creates a product", response.status_code == 201, response.text[:160])
    product_id = response.json()["id"]
    response = client.post(
        "/api/orders",
        json={"payment_method": "CASH", "items": [{"product_id": product_id, "quantity": 1}], "amount_paid": 100},
        headers=admin,
    )
    check("admin creates a cash order", response.status_code == 201, response.text[:200])
    settings = client.get("/api/settings", headers=admin).json()["settings"]
    check("admin sees the merchant settings", "profile_id" in settings and "secret_key" in settings)
    check("the payment secret is masked", "*" in settings.get("secret_key", ""), settings.get("secret_key"))
    check("admin can download a backup", client.get("/api/data/backup", headers=admin).status_code == 200)
    check("admin can list users", client.get("/api/auth/users", headers=admin).status_code == 200)

    # --- staff accounts -----------------------------------------------------
    response = client.post(
        "/api/auth/users",
        json={"username": "cashier1", "password": "CashierPass123", "role": "cashier"},
        headers=admin,
    )
    check("admin creates a cashier", response.status_code == 201, response.text[:160])
    cashier_id = response.json()["id"]
    check("weak passwords are refused",
          client.post("/api/auth/users", json={"username": "weak1", "password": "12345678"},
                      headers=admin).status_code == 400)
    check("duplicate usernames are refused",
          client.post("/api/auth/users", json={"username": "cashier1", "password": "CashierPass123"},
                      headers=admin).status_code == 409)

    response = client.post("/api/auth/login", json={"username": "cashier1", "password": "CashierPass123"})
    check("cashier signs in", response.status_code == 200, response.text[:160])
    cashier = {"Authorization": f"Bearer {response.json()['token']}"}

    # --- what a cashier may NOT do -----------------------------------------
    refused = 0
    for method, path, body in CASHIER_DENIED:
        path = path.format(pid=product_id)
        kwargs = {"json": body} if body is not None else {}
        response = getattr(client, method)(path, headers=cashier, **kwargs)
        if response.status_code == 403:
            refused += 1
        else:
            print(f"      -> cashier {method.upper()} {path} returned {response.status_code}: {response.text[:120]}")
    check("cashiers cannot create/modify/export data", refused == len(CASHIER_DENIED),
          f"{refused}/{len(CASHIER_DENIED)} returned 403")

    # --- what a cashier MAY do ---------------------------------------------
    response = client.post(
        "/api/orders",
        json={"payment_method": "CASH", "items": [{"product_id": product_id, "quantity": 1}], "amount_paid": 50},
        headers=cashier,
    )
    check("cashier can still sell", response.status_code == 201, response.text[:160])
    check("cashier can read orders", client.get("/api/orders", headers=cashier).status_code == 200)
    check("cashier can read the catalogue", client.get("/api/products", headers=cashier).status_code == 200)
    public = client.get("/api/settings", headers=cashier).json()["settings"]
    check("cashier settings contain no merchant ids",
          set(public) <= {"merchant_name", "currency", "demo_mode", "amount_decimals"}, str(list(public)))

    # --- self-protection guards --------------------------------------------
    check("admin cannot demote the last administrator",
          client.patch("/api/auth/users/1", json={"role": "cashier"}, headers=admin).status_code == 400)
    check("admin cannot disable its own account",
          client.patch("/api/auth/users/1", json={"is_active": False}, headers=admin).status_code == 400)
    check("admin cannot delete its own account",
          client.delete("/api/auth/users/1", headers=admin).status_code == 400)

    # --- password rotation --------------------------------------------------
    check("wrong current password is refused",
          client.post("/api/auth/password",
                      json={"current_password": "nope", "new_password": "AnotherPass123"},
                      headers=cashier).status_code == 400)
    check("cashier can change its own password",
          client.post("/api/auth/password",
                      json={"current_password": "CashierPass123", "new_password": "AnotherPass123"},
                      headers=cashier).status_code == 200)
    check("old password stops working",
          client.post("/api/auth/login",
                      json={"username": "cashier1", "password": "CashierPass123"}).status_code == 401)
    response = client.post("/api/auth/login", json={"username": "cashier1", "password": "AnotherPass123"})
    check("new password works", response.status_code == 200)
    rotating = {"Authorization": f"Bearer {response.json()['token']}"}

    # --- disabled account ---------------------------------------------------
    check("admin disables the cashier",
          client.patch(f"/api/auth/users/{cashier_id}", json={"is_active": False},
                       headers=admin).status_code == 200)
    check("a disabled account cannot sign in",
          client.post("/api/auth/login",
                      json={"username": "cashier1", "password": "AnotherPass123"}).status_code == 401)
    check("an existing session of a disabled account stops working",
          client.get("/api/orders", headers=rotating).status_code == 401)

    # --- logout -------------------------------------------------------------
    response = client.post("/api/auth/login", json={"username": "admin", "password": "TestAdminPass123"})
    temp = {"Authorization": f"Bearer {response.json()['token']}"}
    check("temp token works", client.get("/api/auth/me", headers=temp).status_code == 200)
    check("logout succeeds", client.post("/api/auth/logout", headers=temp).status_code == 200)
    check("a revoked token is rejected", client.get("/api/auth/me", headers=temp).status_code == 401)

    # --- audit trail --------------------------------------------------------
    audit = client.get("/api/auth/audit?limit=300", headers=admin).json()
    actions = " ".join(f"{row.get('action')} {row.get('detail')}" for row in audit)
    check("failed sign-ins are recorded", "failed sign-in" in actions)
    check("anonymous attempts are recorded", any(row.get("username") == "anonymous" for row in audit))
    check("password changes are recorded", "password change" in actions)
    check("403 rejections are recorded", any(row.get("status_code") == 403 for row in audit))
    check("who created the product is recorded",
          any("create a product" in str(row.get("action")).lower() or
              (row.get("path") == "/api/products" and row.get("method") == "POST" and row.get("status_code") == 201)
              for row in audit))

    # --- the payment redirect cannot settle an unsigned order --------------
    from database import SessionLocal
    from models import Order

    db = SessionLocal()
    try:
        order = Order(order_number="POS-TEST-000001", transaction_id="TESTTX0001",
                      payment_method="KHQR", status="PENDING", subtotal=10.0, total=10.0, currency="USD")
        db.add(order)
        db.commit()
        order_id = order.id
    finally:
        db.close()

    response = client.get("/api/payment/return?transaction_id=TESTTX0001&status=0&success_amount=10.00",
                          follow_redirects=False)
    check("payment/return redirects the customer", response.status_code in (302, 307), response.status_code)
    db = SessionLocal()
    try:
        db.expire_all()
        check("unsigned payment/return did NOT settle the order",
              db.get(Order, order_id).status == "PENDING")
    finally:
        db.close()

    # --- brute force --------------------------------------------------------
    status = 0
    for _ in range(7):
        status = client.post("/api/auth/login",
                             json={"username": "lockeduser", "password": "guessme123"}).status_code
    check("brute force gets locked out", status == 429, status)

    # --- the ABA webhook stays public but must be signed -------------------
    check("unsigned webhook is refused",
          client.post("/api/webhook/aba",
                      json={"transaction_id": "TESTTX0001", "amount": "10.00",
                            "status": "SUCCESS", "hash": "deadbeef"}).status_code in (401, 400))
    check("webhook probe stays reachable", client.get("/api/webhook/aba").status_code == 200)
    print("\n" + "=" * 60)
    print(f"FAILED CHECKS: {len(FAILED)}" + ("" if not FAILED else " -> " + ", ".join(FAILED)))
    print("=" * 60)
    return len(FAILED)


with TestClient(main.app) as test_client:
    failures = run(test_client)

# Tidy up: dispose the engine so SQLite releases the throwaway file.
try:
    from database import engine

    engine.dispose()
    if TEST_DB.exists():
        TEST_DB.unlink()
except OSError:  # pragma: no cover - Windows may keep the file locked briefly
    print(f"(left {TEST_DB.name} behind - delete it manually)")

raise SystemExit(1 if failures else 0)
