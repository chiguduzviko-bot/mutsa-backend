import re
import uuid

from flask import request
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    jwt_required,
    verify_jwt_in_request,
)
from flask_restx import Namespace, Resource, fields

from app import db
from app import limiter
from app.models.user import User, UserRole
from app.utils.audit import write_audit

auth_ns = Namespace("auth", description="Authentication operations")

register_model = auth_ns.model(
    "RegisterInput",
    {
        "employee_number": fields.String(required=True),
        "full_name": fields.String(required=True),
        "email": fields.String(required=True),
        "phone": fields.String(required=False),
        "role": fields.String(required=False, enum=[r.value for r in UserRole]),
        "password": fields.String(required=True),
    },
)

login_model = auth_ns.model(
    "LoginInput",
    {
        "email": fields.String(required=True),
        "password": fields.String(required=True),
    },
)

change_password_model = auth_ns.model(
    "ChangePasswordInput",
    {
        "current_password": fields.String(required=True),
        "new_password": fields.String(required=True),
    },
)


def _response(success, data=None, message="", status=200):
    return {"success": success, "data": data or {}, "message": message}, status


def _is_valid_email(email):
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email or ""))


def _to_uuid(value):
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        return None


def _normalize_role_value(role_value):
    """Always returns uppercase string: ADMIN or AUDITOR."""
    return User.normalize_role_value(role_value).value


def _serialize_user(user):
    return {
        "id": str(user.id),
        "employee_number": user.employee_number,
        "full_name": user.full_name,
        "email": user.email,
        "phone": user.phone,
        "role": _normalize_role_value(user.role),
        "is_active": user.is_active,
    }


def _get_current_user():
    identity = _to_uuid(get_jwt_identity())
    if not identity:
        return None
    return User.query.filter_by(id=identity, is_active=True).first()


@auth_ns.route("/register")
class RegisterResource(Resource):
    @auth_ns.expect(register_model, validate=True)
    def post(self):
        data = request.get_json() or {}
        required_fields = ["employee_number", "full_name", "email", "password"]
        missing = [f for f in required_fields if not data.get(f)]
        if missing:
            return _response(False, message=f"Missing required fields: {', '.join(missing)}", status=400)
        if not _is_valid_email(data["email"]):
            return _response(False, message="Invalid email format", status=400)
        if len(data["password"]) < 8:
            return _response(False, message="Password must be at least 8 characters", status=400)
        if User.query.filter_by(employee_number=data["employee_number"]).first():
            return _response(False, message="Employee number already exists", status=409)
        if User.query.filter_by(email=data["email"]).first():
            return _response(False, message="Email already exists", status=409)

        raw_role = data.get("role", UserRole.AUDITOR.value)
        try:
            role = User.normalize_role_value(raw_role)
        except ValueError:
            return _response(False, message="Invalid role value. Allowed: ADMIN, AUDITOR", status=400)

        if role != UserRole.AUDITOR:
            verify_jwt_in_request()
            current_user = _get_current_user()
            if not current_user or current_user.role != UserRole.ADMIN:
                return _response(False, message="Only admins can assign ADMIN role", status=403)

        user = User(
            employee_number=data["employee_number"],
            full_name=data["full_name"],
            email=data["email"],
            phone=data.get("phone"),
            role=role,
        )
        user.set_password(data["password"])
        db.session.add(user)
        db.session.commit()

        return _response(
            True,
            data={"user": _serialize_user(user)},
            message="User registered successfully",
            status=201,
        )


@auth_ns.route("/login")
class LoginResource(Resource):
    @auth_ns.expect(login_model, validate=True)
    @limiter.limit("5 per minute")
    def post(self):
        data = request.get_json() or {}
        if not data.get("email") or not data.get("password"):
            return _response(False, message="Email and password are required", status=400)

        user = User.query.filter_by(email=data["email"]).first()
        if not user or not user.is_active or not user.check_password(data["password"]):
            # Write failed-login audit without user_id to avoid leaking existence
            write_audit(
                "LOGIN_FAILED",
                entity_type="AUTH",
                details={"email": data.get("email")},
                metadata={"result": "invalid_credentials"},
                request=request,
            )
            return _response(False, message="Invalid credentials", status=401)

        role_str = _normalize_role_value(user.role)
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={"role": role_str, "email": user.email},
        )
        refresh_token = create_refresh_token(
            identity=str(user.id),
            additional_claims={"role": role_str, "email": user.email},
        )

        write_audit(
            "LOGIN",
            actor_user_id=user.id,
            actor_role=role_str,
            entity_type="AUTH",
            details={"result": "success"},
            metadata={"result": "success"},
            request=request,
        )

        return _response(
            True,
            data={
                "access_token": access_token,
                "refresh_token": refresh_token,
                "user": _serialize_user(user),
            },
            message="Login successful",
        )


@auth_ns.route("/logout")
class LogoutResource(Resource):
    @jwt_required()
    def post(self):
        user = _get_current_user()
        write_audit(
            "LOGOUT",
            actor_user_id=user.id if user else None,
            actor_role=_normalize_role_value(user.role) if user else None,
            entity_type="AUTH",
            details={"triggered_by": "user"},
            request=request,
        )
        return _response(True, message="Logged out successfully")


@auth_ns.route("/refresh")
class RefreshResource(Resource):
    @jwt_required(refresh=True)
    def post(self):
        user = _get_current_user()
        if not user:
            return _response(False, message="User not found", status=404)

        role_str = _normalize_role_value(user.role)
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={"role": role_str, "email": user.email},
        )
        return _response(True, data={"access_token": access_token}, message="Access token refreshed")


@auth_ns.route("/me")
class MeResource(Resource):
    @jwt_required()
    def get(self):
        user = _get_current_user()
        if not user:
            return _response(False, message="User not found", status=404)
        return _response(
            True,
            data={"user": _serialize_user(user)},
            message="Current user profile",
        )


@auth_ns.route("/change-password")
class ChangePasswordResource(Resource):
    @auth_ns.expect(change_password_model, validate=True)
    @jwt_required()
    def put(self):
        data = request.get_json() or {}
        if not data.get("current_password") or not data.get("new_password"):
            return _response(False, message="Current and new password are required", status=400)
        if len(data["new_password"]) < 8:
            return _response(False, message="New password must be at least 8 characters", status=400)
        if data["current_password"] == data["new_password"]:
            return _response(False, message="New password must be different from current password", status=400)

        user = _get_current_user()
        if not user:
            return _response(False, message="User not found", status=404)
        if not user.check_password(data["current_password"]):
            return _response(False, message="Current password is incorrect", status=400)

        user.set_password(data["new_password"])
        db.session.commit()
        return _response(True, message="Password changed successfully")
