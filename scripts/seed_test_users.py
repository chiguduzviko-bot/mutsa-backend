"""
Seed one user per role for local/staging QA. Do not use these passwords in production.

Run from chain_custody_api directory:
    python scripts/seed_test_users.py

Requires DATABASE_URL / SQLALCHEMY_DATABASE_URI (or .env) pointing at your Postgres DB.
Login identifier is email (there is no separate username column).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app, db
from app.models.user import User, UserRole

# Dev-only credentials — rotate in any shared or production environment
SEED_USERS: list[dict] = [
    {
        "email": "admin@test.coc.local",
        "full_name": "Test Admin",
        "role": UserRole.ADMIN,
        "password": "AdminTest123!",
        "employee_number": "EMP-TST-ADMIN",
    },
    {
        "email": "investigator@test.coc.local",
        "full_name": "Test Investigator",
        "role": UserRole.INVESTIGATOR,
        "password": "InvestigatorTest123!",
        "employee_number": "EMP-TST-INV",
    },
    {
        "email": "authorizer@test.coc.local",
        "full_name": "Test Authorizer",
        "role": UserRole.AUTHORIZER,
        "password": "AuthorizerTest123!",
        "employee_number": "EMP-TST-AUTHZ",
    },
    {
        "email": "auditor@test.coc.local",
        "full_name": "Test Auditor",
        "role": UserRole.AUDITOR,
        "password": "AuditorTest123!",
        "employee_number": "EMP-TST-AUD",
    },
]


def upsert_user(email: str, full_name: str, role: UserRole, password: str, employee_number: str) -> str:
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(
            employee_number=employee_number,
            full_name=full_name,
            email=email,
            role=role,
            is_active=True,
        )
        db.session.add(user)
        action = "created"
    else:
        user.full_name = full_name
        user.role = role
        user.employee_number = employee_number
        user.is_active = True
        action = "updated"
    user.set_password(password)
    return action


def main() -> None:
    app = create_app()
    with app.app_context():
        for spec in SEED_USERS:
            action = upsert_user(
                email=spec["email"],
                full_name=spec["full_name"],
                role=spec["role"],
                password=spec["password"],
                employee_number=spec["employee_number"],
            )
            print(f"[{action}] {spec['role'].value:<12} {spec['email']}")

        db.session.commit()

    print()
    print("=== Test users (login with email + password) ===")
    print(f"{'Role':<14} {'Email (login)':<38} {'Password':<26} {'Display name'}")
    print("-" * 110)
    for spec in SEED_USERS:
        print(
            f"{spec['role'].value:<14} "
            f"{spec['email']:<38} "
            f"{spec['password']:<26} "
            f"{spec['full_name']}"
        )
    print()
    print("There is no separate username field; use the email column as the login id.")


if __name__ == "__main__":
    main()
