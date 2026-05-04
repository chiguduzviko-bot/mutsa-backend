import uuid

from flask import request
from flask_jwt_extended import jwt_required
from flask_restx import Namespace, Resource, fields

from app import db
from app.models.user import User, UserRole
from app.utils.decorators import requireRole

users_ns = Namespace("users", description="User management operations")

user_create_model = users_ns.model(
    "UserCreateInput",
    {
        "full_name": fields.String(required=True),
        "email": fields.String(required=True),
        "password": fields.String(required=True),
        "role": fields.String(required=True, enum=[r.value for r in UserRole]),
    },
)


def _response(success, data=None, message="", status=200):
    return {"success": success, "data": data or {}, "message": message}, status


def _generate_employee_number():
    for _ in range(20):
        candidate = f"EMP-{uuid.uuid4().hex[:8].upper()}"
        if not User.query.filter_by(employee_number=candidate).first():
            return candidate
    raise RuntimeError("Failed to generate unique employee number")


def _serialize_user(user):
    return {
        "id": str(user.id),
        "email": user.email,
        "full_name": user.full_name,
        "role": str(getattr(user.role, "value", user.role)).strip().upper(),
    }


@users_ns.route("")
class UserManagementResource(Resource):
    @requireRole("ADMIN")
    @jwt_required()
    def get(self):
        users = User.query.order_by(User.created_at.desc()).all()
        return _response(
            True,
            data={"users": [_serialize_user(user) for user in users]},
            message="Users fetched",
        )

    @users_ns.expect(user_create_model, validate=True)
    @requireRole("ADMIN")
    @jwt_required()
    def post(self):
        data = request.get_json() or {}
        full_name = (data.get("full_name") or "").strip()
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        role_raw = data.get("role")

        if not full_name or not email or not password or not role_raw:
            return _response(False, message="full_name, email, password and role are required", status=400)
        if len(password) < 8:
            return _response(False, message="Password must be at least 8 characters", status=400)
        if User.query.filter_by(email=email).first():
            return _response(False, message="Email already exists", status=409)

        try:
            role = User.normalize_role_value(role_raw)
        except ValueError:
            return _response(False, message="Invalid role value", status=400)

        user = User(
            employee_number=_generate_employee_number(),
            full_name=full_name,
            email=email,
            role=role,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        return _response(True, data=_serialize_user(user), status=201)
