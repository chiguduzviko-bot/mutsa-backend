"""Tests: auth responses, RBAC enforcement, audit events, flags, CSV export."""
import io
import uuid

import pytest
from flask_jwt_extended import create_access_token

from app import create_app
from app.models.user import UserRole


# ─── Fake helpers ─────────────────────────────────────────────────────────────

class FakeUser:
    def __init__(self, *, role=UserRole.AUDITOR, email="user@test.local", full_name="Test User"):
        self.id = uuid.uuid4()
        self.employee_number = f"EMP-{str(self.id)[:6].upper()}"
        self.full_name = full_name
        self.email = email
        self.phone = None
        self.role = role
        self.is_active = True

    def check_password(self, _pw):
        return True


class FakeQuery:
    def __init__(self, responder):
        self._responder = responder
        self._filters = {}

    def filter_by(self, **kwargs):
        self._filters = kwargs
        return self

    def first(self):
        return self._responder(self._filters)


class FakeRowsQuery:
    """Stub for SQLAlchemy query chains used in admin list endpoints."""
    def filter(self, *_a, **_k): return self
    def filter_by(self, **_k): return self
    def count(self): return 0
    def order_by(self, *_a): return self
    def offset(self, *_a): return self
    def limit(self, *_a): return self
    def all(self): return []
    def with_entities(self, *_a): return self
    def scalar(self): return 0
    def join(self, *_a, **_k): return self


# ─── App fixture ──────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def app():
    flask_app = create_app()
    flask_app.config["TESTING"] = True
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


# ─── Role-normalization unit test ─────────────────────────────────────────────

class TestUserRoleNormalization:
    def test_investigator_mapped_to_auditor(self):
        from app.models.user import User
        result = User.normalize_role_value("INVESTIGATOR")
        assert result == UserRole.AUDITOR

    def test_supervisor_mapped_to_auditor(self):
        from app.models.user import User
        result = User.normalize_role_value("SUPERVISOR")
        assert result == UserRole.AUDITOR

    def test_admin_preserved(self):
        from app.models.user import User
        result = User.normalize_role_value("ADMIN")
        assert result == UserRole.ADMIN

    def test_auditor_preserved(self):
        from app.models.user import User
        result = User.normalize_role_value("AUDITOR")
        assert result == UserRole.AUDITOR

    def test_lowercase_normalized(self):
        from app.models.user import User
        result = User.normalize_role_value("admin")
        assert result == UserRole.ADMIN

    def test_invalid_role_raises(self):
        from app.models.user import User
        with pytest.raises(ValueError):
            User.normalize_role_value("UNKNOWN_ROLE")


# ─── Auth: login ──────────────────────────────────────────────────────────────

class TestLogin:
    def test_admin_login_returns_role_in_user_payload(self, client, monkeypatch):
        admin = FakeUser(role=UserRole.ADMIN, email="admin@test.local")

        monkeypatch.setattr(
            "app.routes.auth.User.query",
            FakeQuery(lambda f: admin if f.get("email") == admin.email else None),
        )
        monkeypatch.setattr("app.utils.audit.db.session.add", lambda *_: None)
        monkeypatch.setattr("app.utils.audit.db.session.commit", lambda: None)

        res = client.post("/api/auth/login", json={"email": admin.email, "password": "pw"})
        assert res.status_code == 200
        body = res.get_json()
        assert body["success"] is True
        assert body["data"]["user"]["role"] == "ADMIN"
        assert "access_token" in body["data"]
        assert "refresh_token" in body["data"]

    def test_auditor_login_returns_auditor_role(self, client, monkeypatch):
        auditor = FakeUser(role=UserRole.AUDITOR, email="aud@test.local")

        monkeypatch.setattr(
            "app.routes.auth.User.query",
            FakeQuery(lambda f: auditor if f.get("email") == auditor.email else None),
        )
        monkeypatch.setattr("app.utils.audit.db.session.add", lambda *_: None)
        monkeypatch.setattr("app.utils.audit.db.session.commit", lambda: None)

        res = client.post("/api/auth/login", json={"email": auditor.email, "password": "pw"})
        assert res.status_code == 200
        assert res.get_json()["data"]["user"]["role"] == "AUDITOR"

    def test_invalid_credentials_returns_401(self, client, monkeypatch):
        monkeypatch.setattr(
            "app.routes.auth.User.query",
            FakeQuery(lambda _: None),
        )
        monkeypatch.setattr("app.utils.audit.db.session.add", lambda *_: None)
        monkeypatch.setattr("app.utils.audit.db.session.commit", lambda: None)

        res = client.post("/api/auth/login", json={"email": "x@x.com", "password": "wrong"})
        assert res.status_code == 401


# ─── Auth: /me ────────────────────────────────────────────────────────────────

class TestMe:
    def _make_token(self, app, user):
        with app.app_context():
            return create_access_token(
                identity=str(user.id),
                additional_claims={"role": user.role.value},
            )

    def test_me_returns_auditor_role(self, app, client, monkeypatch):
        user = FakeUser(role=UserRole.AUDITOR, email="aud@test.local")

        monkeypatch.setattr(
            "app.routes.auth.User.query",
            FakeQuery(lambda f: user if str(f.get("id")) == str(user.id) else None),
        )
        token = self._make_token(app, user)
        res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200
        data = res.get_json()["data"]["user"]
        assert data["role"] == "AUDITOR"
        assert data["email"] == user.email

    def test_me_returns_admin_role(self, app, client, monkeypatch):
        user = FakeUser(role=UserRole.ADMIN, email="adm@test.local")

        monkeypatch.setattr(
            "app.routes.auth.User.query",
            FakeQuery(lambda f: user if str(f.get("id")) == str(user.id) else None),
        )
        token = self._make_token(app, user)
        res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res.get_json()["data"]["user"]["role"] == "ADMIN"


# ─── RBAC enforcement ─────────────────────────────────────────────────────────

class TestRBAC:
    def _token(self, app, user):
        with app.app_context():
            return create_access_token(
                identity=str(user.id),
                additional_claims={"role": user.role.value},
            )

    def _patch_decorator_query(self, monkeypatch, *users):
        user_map = {str(u.id): u for u in users}
        monkeypatch.setattr(
            "app.utils.decorators.User.query",
            FakeQuery(lambda f: user_map.get(str(f.get("id")))),
        )

    def _patch_admin_routes(self, monkeypatch):
        monkeypatch.setattr("app.routes.admin._log_with_joins", FakeRowsQuery)
        monkeypatch.setattr("app.routes.admin._apply_log_filters", lambda q: q)

    def test_admin_can_access_log_list(self, app, client, monkeypatch):
        admin = FakeUser(role=UserRole.ADMIN)
        self._patch_decorator_query(monkeypatch, admin)
        self._patch_admin_routes(monkeypatch)
        token = self._token(app, admin)
        res = client.get("/api/admin/evidence-access-log", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200

    def test_auditor_can_access_log_list(self, app, client, monkeypatch):
        auditor = FakeUser(role=UserRole.AUDITOR)
        self._patch_decorator_query(monkeypatch, auditor)
        self._patch_admin_routes(monkeypatch)
        token = self._token(app, auditor)
        res = client.get("/api/admin/evidence-access-log", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200

    def test_auditor_can_access_stats(self, app, client, monkeypatch):
        auditor = FakeUser(role=UserRole.AUDITOR)
        self._patch_decorator_query(monkeypatch, auditor)
        monkeypatch.setattr(
            "app.routes.admin.EvidenceAccessLog.query",
            FakeRowsQuery(),
        )
        token = self._token(app, auditor)
        res = client.get("/api/admin/evidence-access-log/stats", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200

    def test_auditor_cannot_resolve_flag(self, app, client, monkeypatch):
        auditor = FakeUser(role=UserRole.AUDITOR)
        self._patch_decorator_query(monkeypatch, auditor)
        token = self._token(app, auditor)
        fake_id = str(uuid.uuid4())
        res = client.patch(
            f"/api/admin/evidence-access-log/flags/{fake_id}",
            json={"status": "REVIEWED"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 403

    def test_admin_can_resolve_flag(self, app, client, monkeypatch):
        admin = FakeUser(role=UserRole.ADMIN)
        self._patch_decorator_query(monkeypatch, admin)
        # Stub flag lookup
        fake_flag = type("Flag", (), {
            "id": uuid.uuid4(),
            "audit_log_id": uuid.uuid4(),
            "flagged_by_user_id": uuid.uuid4(),
            "reason": "test",
            "category": "OTHER",
            "status": "OPEN",
            "created_at": None,
            "updated_at": None,
        })()
        monkeypatch.setattr(
            "app.routes.admin.AuditLogFlag.query",
            FakeQuery(lambda f: fake_flag),
        )
        monkeypatch.setattr("app.routes.admin.db.session.commit", lambda: None)
        token = self._token(app, admin)
        res = client.patch(
            f"/api/admin/evidence-access-log/flags/{fake_flag.id}",
            json={"status": "REVIEWED"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 200

    def test_unauthenticated_rejected(self, app, client):
        res = client.get("/api/admin/evidence-access-log")
        assert res.status_code in (401, 422)


# ─── Audit event tests ────────────────────────────────────────────────────────

class TestAuditEvents:
    def test_login_writes_audit(self, client, monkeypatch):
        user = FakeUser(role=UserRole.AUDITOR, email="login_audit@test.local")
        monkeypatch.setattr(
            "app.routes.auth.User.query",
            FakeQuery(lambda f: user if f.get("email") == user.email else None),
        )

        written = []
        monkeypatch.setattr("app.utils.audit.db.session.add", lambda row: written.append(row))
        monkeypatch.setattr("app.utils.audit.db.session.commit", lambda: None)

        client.post("/api/auth/login", json={"email": user.email, "password": "pw"})
        assert any(getattr(r, "action", None) == "LOGIN" for r in written)

    def test_failed_login_writes_login_failed_audit(self, client, monkeypatch):
        monkeypatch.setattr(
            "app.routes.auth.User.query",
            FakeQuery(lambda _: None),
        )
        written = []
        monkeypatch.setattr("app.utils.audit.db.session.add", lambda row: written.append(row))
        monkeypatch.setattr("app.utils.audit.db.session.commit", lambda: None)

        client.post("/api/auth/login", json={"email": "no@one.local", "password": "bad"})
        assert any(getattr(r, "action", None) == "LOGIN_FAILED" for r in written)

    def test_logout_writes_audit(self, app, client, monkeypatch):
        user = FakeUser(role=UserRole.AUDITOR, email="logout@test.local")
        monkeypatch.setattr(
            "app.routes.auth.User.query",
            FakeQuery(lambda f: user if str(f.get("id")) == str(user.id) else None),
        )
        written = []
        monkeypatch.setattr("app.utils.audit.db.session.add", lambda row: written.append(row))
        monkeypatch.setattr("app.utils.audit.db.session.commit", lambda: None)

        with app.app_context():
            token = create_access_token(
                identity=str(user.id),
                additional_claims={"role": user.role.value},
            )
        client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert any(getattr(r, "action", None) == "LOGOUT" for r in written)


# ─── CSV export structure ─────────────────────────────────────────────────────

class TestCSVExport:
    EXPECTED_HEADERS = {
        "timestamp", "user_name", "user_role", "badge_number",
        "action", "evidence_ref", "case_number", "hash_at_time",
        "session_event", "ip_address",
    }

    def test_csv_has_correct_headers(self, app, client, monkeypatch):
        admin = FakeUser(role=UserRole.ADMIN)
        monkeypatch.setattr(
            "app.utils.decorators.User.query",
            FakeQuery(lambda f: admin if str(f.get("id")) == str(admin.id) else None),
        )
        monkeypatch.setattr("app.routes.admin._log_with_joins", FakeRowsQuery)
        monkeypatch.setattr("app.routes.admin._apply_log_filters", lambda q: q)

        with app.app_context():
            token = create_access_token(
                identity=str(admin.id),
                additional_claims={"role": admin.role.value},
            )
        res = client.get(
            "/api/admin/evidence-access-log/export",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 200
        assert "text/csv" in res.content_type
        first_line = res.data.decode("utf-8").splitlines()[0]
        headers_found = {h.strip() for h in first_line.split(",")}
        assert self.EXPECTED_HEADERS == headers_found
