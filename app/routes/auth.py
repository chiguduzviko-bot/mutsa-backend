import re
import traceback
import uuid

from flask import current_app, request
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_jwt_identity,
    jwt_required,
    verify_jwt_in_request,
)
from flask_restx import Namespace, Resource, fields
from sqlalchemy.exc import SQLAlchemyError

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
    """Always returns uppercase role string from UserRole."""
    return User.normalize_role_value(role_value).value


def _is_admin_role(role_value):
    return str(getattr(role_value, "value", role_value)).strip().upper() == "ADMIN"


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
            return _response(
                False,
                message="Invalid role value. Allowed: ADMIN, AUDITOR, INVESTIGATOR, AUTHORIZER",
                status=400,
            )

        if role != UserRole.AUDITOR:
            verify_jwt_in_request()
            current_user = _get_current_user()
            if not current_user or not _is_admin_role(current_user.role):
                return _response(False, message="Only admins can assign elevated roles", status=403)

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
        try:
            data = request.get_json(silent=True) or {}
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
                return {"success": False, "message": "Invalid email or password."}, 401

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

            user_payload = _serialize_user(user)
            return {
                "success": True,
                "data": {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": {
                        "id": user_payload["id"],
                        "email": user_payload["email"],
                        "full_name": user_payload["full_name"],
                        "role": user_payload["role"],
                    },
                },
            }, 200
        except SQLAlchemyError:
            db.session.rollback()
            current_app.logger.exception("Database error during login")
            return {"success": False, "message": "Database temporarily unavailable."}, 503
        except Exception as exc:
            db.session.rollback()
            traceback.print_exc()
            return {"success": False, "message": str(exc)}, 500


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
    def post(self):
        body = request.get_json(silent=True) or {}
        refresh_token = body.get("refresh_token")
        if not refresh_token:
            return {"success": False, "message": "refresh_token is required"}, 400

        try:
            decoded = decode_token(refresh_token)
        except Exception:
            return {"success": False, "message": "Invalid refresh token"}, 401

        if decoded.get("type") != "refresh":
            return {"success": False, "message": "Invalid refresh token"}, 401

        user = User.query.filter_by(id=_to_uuid(decoded.get("sub")), is_active=True).first()
        if not user:
            return _response(False, message="User not found", status=404)

        role_str = _normalize_role_value(user.role)
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={"role": role_str, "email": user.email},
        )
        return {"success": True, "data": {"access_token": access_token}}, 200


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
