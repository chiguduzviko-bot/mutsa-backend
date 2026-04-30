from datetime import datetime

from sqlalchemy.dialects.postgresql import UUID

from app import db


class FileHash(db.Model):
    __tablename__ = "file_hashes"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    evidence_id = db.Column(UUID(as_uuid=True), db.ForeignKey("evidence.id"), nullable=False)
    algorithm = db.Column(db.String(16), nullable=False, default="SHA-256")
    sha256_hash = db.Column(db.String(64), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    file_size_bytes = db.Column(db.BigInteger)
    hashed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    hashed_by_user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"))
    is_current = db.Column(db.Boolean, nullable=False, default=True)
