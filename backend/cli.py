import argparse
import getpass
import os
import re
import sys

from backend import models
from backend.auth.auth import hash_password
from backend.config import IS_PRODUCTION
from backend.database import SessionLocal, init_db


def create_admin(args: argparse.Namespace) -> int:
    password = os.getenv("CS_ADMIN_PASSWORD") or getpass.getpass("Admin password (min 12 chars): ")
    if len(password) < 12:
        print("Password must be at least 12 characters.", file=sys.stderr)
        return 1
    if not IS_PRODUCTION:
        init_db()
    slug = re.sub(r"[^a-z0-9]+", "-", args.org.lower()).strip("-") or "org"
    with SessionLocal() as db:
        if db.query(models.User).filter(models.User.username == args.username).first():
            print("Username already exists.", file=sys.stderr)
            return 1
        org = db.query(models.Organization).filter(models.Organization.slug == slug).first()
        if org is None:
            org = models.Organization(
                name=args.org, slug=slug, status="ACTIVE", environment="PRODUCTION" if IS_PRODUCTION else "DEMO"
            )
            db.add(org)
            db.flush()
        db.add(
            models.User(
                organization_id=org.id,
                username=args.username,
                password_hash=hash_password(password),
                display_name=args.display_name or args.username,
                role="admin",
                email=args.email,
                is_active=True,
            )
        )
        db.commit()
    print(f"Admin '{args.username}' created in organization '{args.org}'.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m backend.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("create-admin", help="Create an organization admin (password via prompt or CS_ADMIN_PASSWORD)")
    c.add_argument("--username", required=True)
    c.add_argument("--email", required=True)
    c.add_argument("--org", required=True, help="Organization name")
    c.add_argument("--display-name")
    c.set_defaults(func=create_admin)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
