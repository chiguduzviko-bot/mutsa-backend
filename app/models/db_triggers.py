from sqlalchemy import DDL, event

from app import db


def register_db_triggers():
    custody_update_guard = DDL(
        """
        CREATE OR REPLACE FUNCTION prevent_custody_log_mutation()
        RETURNS TRIGGER
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'custody_log is append-only. %% is not permitted.', TG_OP
                USING ERRCODE = '55000';
        END;
        $$;
        """
    )
    custody_update_trigger = DDL(
        """
        CREATE TRIGGER trg_custody_log_no_update_delete
        BEFORE UPDATE OR DELETE ON custody_log
        FOR EACH ROW EXECUTE FUNCTION prevent_custody_log_mutation();
        """
    )

    event.listen(db.metadata, "after_create", custody_update_guard.execute_if(dialect="postgresql"))
    event.listen(db.metadata, "after_create", custody_update_trigger.execute_if(dialect="postgresql"))
