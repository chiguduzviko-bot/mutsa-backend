from app import create_app, db
from app.models.user import User, UserRole


def upsert_user(email, full_name, role, password, employee_number):
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(
            employee_number=employee_number,
            full_name=full_name,
            email=email,
            role=UserRole(role),
            is_active=True,
        )
        db.session.add(user)
    else:
        user.full_name = full_name
        user.role = UserRole(role)
        user.employee_number = employee_number
        user.is_active = True

    user.set_password(password)


def main():
    app = create_app()
    with app.app_context():
        upsert_user(
            email="admin@example.com",
            full_name="Admin User",
            role="ADMIN",
            password="Admin1234!",
            employee_number="ADM001",
        )
        upsert_user(
            email="auditor@example.com",
            full_name="Audit User",
            role="AUDITOR",
            password="Audit1234!",
            employee_number="AUD001",
        )
        db.session.commit()
        print("Seeded users: admin@example.com, auditor@example.com")


if __name__ == "__main__":
    main()
