"""Offline administration for the POS (run on the machine hosting the API).

Physical access to the till is the trust boundary here, so this tool needs no
password - which also makes it the "I locked myself out" recovery path.

    python manage.py list                      # who exists
    python manage.py add-user sreyneang --role cashier
    python manage.py passwd admin              # rotate a password (prompts)
    python manage.py passwd cashier1 MyPass12  # non-interactive
    python manage.py role cashier1 admin
    python manage.py disable cashier1          # enable / delete work the same way
    python manage.py revoke-tokens             # sign every device out
"""
from __future__ import annotations

import argparse
import getpass
import sys

import security
from database import SessionLocal, init_db
from fastapi import HTTPException
from models import AuthToken, User


def _reject(exc: HTTPException) -> int:
    """Turn a validation refusal into a friendly CLI message."""
    print(f"Refused: {exc.detail}")
    return 1


def _find(db, username: str) -> User:
    user = security.get_user(db, username)
    if user is None:
        print(f"No such user: {username}")
        sys.exit(1)
    return user


def _read_password(username: str, provided: str | None) -> str:
    if provided:
        return provided
    first = getpass.getpass(f"New password for {username}: ")
    again = getpass.getpass("Repeat the password: ")
    if first != again:
        print("The two passwords do not match.")
        sys.exit(1)
    return first


def _print_users(db) -> None:
    rows = db.query(User).order_by(User.username).all()
    if not rows:
        print("No users yet - start the API once to create the first administrator.")
        return
    print(f"{'id':>3}  {'username':<20} {'role':<8} {'active':<7} last login")
    for user in rows:
        last = user.last_login_at.isoformat(sep=" ", timespec="seconds") if user.last_login_at else "-"
        print(
            f"{user.id:>3}  {user.username:<20} {user.role:<8} "
            f"{'yes' if user.is_active else 'no':<7} {last}"
        )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="ABA POS offline admin tool")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list every user")

    node = sub.add_parser("passwd", help="set or rotate a password")
    node.add_argument("username")
    node.add_argument("password", nargs="?", default=None, help="omit to be prompted")

    node = sub.add_parser("add-user", help="create a user")
    node.add_argument("username")
    node.add_argument("password", nargs="?", default=None)
    node.add_argument("--role", choices=list(security.ROLES), default="cashier")
    node.add_argument("--name", default=None, help="display name")

    node = sub.add_parser("role", help="change a role")
    node.add_argument("username")
    node.add_argument("role", choices=list(security.ROLES))

    for name, help_text in (
        ("disable", "block a user from signing in"),
        ("enable", "allow a user to sign in again"),
        ("delete", "remove a user and every session it owns"),
    ):
        node = sub.add_parser(name, help=help_text)
        node.add_argument("username")

    sub.add_parser("revoke-tokens", help="sign every device out")
    sub.add_parser("purge-tokens", help="drop expired sessions")

    args = parser.parse_args(argv)

    init_db()
    db = SessionLocal()
    try:
        if args.command == "list":
            _print_users(db)
            return 0

        if args.command == "revoke-tokens":
            count = db.query(AuthToken).count()
            for row in db.query(AuthToken).all():
                db.delete(row)
            db.commit()
            print(f"Signed out {count} session(s).")
            return 0

        if args.command == "purge-tokens":
            print(f"Removed {security.purge_expired_tokens(db)} expired session(s).")
            return 0

        if args.command == "add-user":
            password = _read_password(args.username, args.password)
            try:
                user = security.create_user(
                    db,
                    username=args.username,
                    password=password,
                    role=args.role,
                    full_name=args.name,
                )
            except HTTPException as exc:
                return _reject(exc)
            print(f"Created {user.username} ({user.role}).")
            return 0

        user = _find(db, args.username)

        if args.command == "passwd":
            password = _read_password(user.username, args.password)
            try:
                security.set_password(db, user, password)
            except HTTPException as exc:
                return _reject(exc)
            print(f"Password updated for {user.username} (all its devices were signed out).")
            return 0

        if args.command == "role":
            if user.role == "admin" and args.role != "admin":
                security.guard_last_admin(db, user, action="demote it")
            user.role = args.role
            db.commit()
            print(f"{user.username} is now '{user.role}'.")
            return 0

        if args.command in ("disable", "enable"):
            if args.command == "disable":
                security.guard_last_admin(db, user, action="disable it")
                user.is_active = False
                security.revoke_tokens(db, user)
            else:
                user.is_active = True
            db.commit()
            print(f"{user.username} is now {'active' if user.is_active else 'disabled'}.")
            return 0

        if args.command == "delete":
            security.guard_last_admin(db, user, action="delete it")
            security.revoke_tokens(db, user)
            db.delete(user)
            db.commit()
            print(f"{user.username} deleted.")
            return 0

        parser.print_help()
        return 1
    finally:
        db.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
