from functools import wraps

from flask import g
from flask_jwt_extended import get_jwt, get_jwt_identity, verify_jwt_in_request

from app.models.user import User


def _normalize_allowed_roles(roles):
    return {str(role).strip().upper() for role in roles}


def requireRole(*allowed_roles):
    """Decorator: verifies JWT and checks the authenticated user's role.

    Usage:
        @requireRole("ADMIN")
        @requireRole("ADMIN", "AUDITOR")
        @requireRole(["ADMIN"])        # list form also accepted
    """
    if len(allowed_roles) == 1 and isinstance(allowed_roles[0], (list, tuple, set)):
        allowed_roles = tuple(allowed_roles[0])
    normalized_allowed = _normalize_allowed_roles(allowed_roles)

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            identity = get_jwt_identity()
            user = User.query.filter_by(id=identity, is_active=True).first()

            # Fall back to JWT claim if DB lookup misses (e.g. token issued before account deactivation)
            jwt_payload = get_jwt() or {}
            claimed_role = str(jwt_payload.get("role", "")).strip().upper()
            resolved_role = user.role.value if user else claimed_role

            if not user or resolved_role not in normalized_allowed:
                return {"success": False, "message": "Forbidden"}, 403

            g.current_user = user
            return fn(*args, **kwargs)

        return wrapper

    return decorator


# Backward-compatible alias
def role_required(*allowed_roles):
    return requireRole(*allowed_roles)
