"""Seed real-name admin and auditor users for testing."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app, db
from app.models.user import User, UserRole

NEW_USERS = [
    # --- ADMIN users ---
    {
        "employee_number": "ADM-1001",
        "full_name":       "James Okonkwo",
        "email":           "james.okonkwo@chaincustody.local",
        "password":        "Admin@James2026",
        "role":            UserRole.ADMIN,
    },
    {
        "employee_number": "ADM-1002",
        "full_name":       "Chiedza Mutasa",
        "email":           "chiedza.mutasa@chaincustody.local",
        "password":        "Admin@Chiedza2026",
        "role":            UserRole.ADMIN,
    },
    {
        "employee_number": "ADM-1003",
        "full_name":       "Tatenda Mwangi",
        "email":           "tatenda.mwangi@chaincustody.local",
        "password":        "Admin@Tatenda2026",
        "role":            UserRole.ADMIN,
    },
    # --- AUDITOR users ---
    {
        "employee_number": "AUD-2001",
        "full_name":       "Farai Ncube",
        "email":           "farai.ncube@chaincustody.local",
        "password":        "Auditor@Farai2026",
        "role":            UserRole.AUDITOR,
    },
    {
        "employee_number": "AUD-2002",
        "full_name":       "Rudo Chirwa",
        "email":           "rudo.chirwa@chaincustody.local",
        "password":        "Auditor@Rudo2026",
        "role":            UserRole.AUDITOR,
    },
    {
        "employee_number": "AUD-2003",
        "full_name":       "Tendai Moyo",
        "email":           "tendai.moyo@chaincustody.local",
        "password":        "Auditor@Tendai2026",
        "role":            UserRole.AUDITOR,
    },
]


def seed():
    app = create_app()
    with app.app_context():
        created, skipped = [], []

        for spec in NEW_USERS:
            if User.query.filter_by(email=spec["email"]).first():
                skipped.append(spec["email"])
                continue
            if User.query.filter_by(employee_number=spec["employee_number"]).first():
                skipped.append(spec["email"] + " (duplicate employee_number)")
                continue

            user = User(
                employee_number=spec["employee_number"],
                full_name=spec["full_name"],
                email=spec["email"],
                role=spec["role"],
                is_active=True,
            )
            user.set_password(spec["password"])
            db.session.add(user)
            created.append(spec)

        db.session.commit()

        sep = "-" * 110
        print(f"\nCreated {len(created)} user(s),  skipped {len(skipped)}.\n")
        print(f"{'ROLE':<10}  {'EMP NO':<12}  {'FULL NAME':<22}  {'EMAIL':<44}  PASSWORD")
        print(sep)
        for s in created:
            print(f"{s['role'].value:<10}  {s['employee_number']:<12}  {s['full_name']:<22}  {s['email']:<44}  {s['password']}")

        if skipped:
            print("\nSkipped (already exist):")
            for e in skipped:
                print(f"  {e}")

        print(f"\n{sep}")
        print("All users now in database:")
        print(sep)
        print(f"{'ROLE':<10}  {'EMP NO':<14}  {'FULL NAME':<28}  EMAIL")
        print(sep)
        for u in User.query.order_by(User.role, User.full_name).all():
            print(f"{u.role.value:<10}  {u.employee_number:<14}  {u.full_name:<28}  {u.email}")


if __name__ == "__main__":
    seed()
