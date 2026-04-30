-- Add evidence_access_log table, helper function, and status-change trigger.
-- This migration only adds new objects and does not recreate existing tables.

CREATE TABLE IF NOT EXISTS evidence_access_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    evidence_id UUID NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    action VARCHAR(100) NOT NULL
        CHECK (action IN (
            'VIEWED',
            'DOWNLOADED',
            'HASH_VERIFIED',
            'TRANSFERRED',
            'STATUS_CHANGED',
            'UPDATED',
            'CREATED'
        )),
    hash_at_time CHAR(64),
    ip_address INET,
    user_agent TEXT,
    notes TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_access_log_evidence_id
    ON evidence_access_log (evidence_id);

CREATE INDEX IF NOT EXISTS idx_evidence_access_log_user_id
    ON evidence_access_log (user_id);

CREATE INDEX IF NOT EXISTS idx_evidence_access_log_case_id
    ON evidence_access_log (case_id);

CREATE INDEX IF NOT EXISTS idx_evidence_access_log_action
    ON evidence_access_log (action);

CREATE INDEX IF NOT EXISTS idx_evidence_access_log_occurred_at
    ON evidence_access_log (occurred_at);


CREATE OR REPLACE FUNCTION log_evidence_access(
    p_evidence_id UUID,
    p_user_id UUID,
    p_action VARCHAR(100),
    p_notes TEXT DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_case_id UUID;
    v_hash_at_time CHAR(64);
BEGIN
    SELECT e.case_id
      INTO v_case_id
      FROM evidence e
     WHERE e.id = p_evidence_id;

    IF v_case_id IS NULL THEN
        RAISE EXCEPTION 'Evidence % not found', p_evidence_id;
    END IF;

    -- Pull the most recent known hash for this evidence item.
    SELECT fh.sha256_hash
      INTO v_hash_at_time
      FROM file_hashes fh
     WHERE fh.evidence_id = p_evidence_id
     ORDER BY fh.verified_at DESC NULLS LAST
     LIMIT 1;

    INSERT INTO evidence_access_log (
        evidence_id,
        case_id,
        user_id,
        action,
        hash_at_time,
        notes
    )
    VALUES (
        p_evidence_id,
        v_case_id,
        p_user_id,
        p_action,
        v_hash_at_time,
        p_notes
    );
END;
$$;


CREATE OR REPLACE FUNCTION trg_log_evidence_status_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_actor UUID;
BEGIN
    -- Application should set app.user_id at session level.
    v_actor := NULLIF(current_setting('app.user_id', true), '')::UUID;

    IF v_actor IS NULL THEN
        RAISE EXCEPTION 'app.user_id is not set; cannot attribute status change';
    END IF;

    PERFORM log_evidence_access(
        NEW.id,
        v_actor,
        'STATUS_CHANGED',
        format('Status changed from %s to %s', OLD.state, NEW.state)
    );

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS tr_evidence_status_access_log ON evidence;

CREATE TRIGGER tr_evidence_status_access_log
AFTER UPDATE OF state ON evidence
FOR EACH ROW
WHEN (OLD.state IS DISTINCT FROM NEW.state)
EXECUTE FUNCTION trg_log_evidence_status_change();
