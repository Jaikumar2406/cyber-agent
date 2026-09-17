-- Immutable audit trail enforcement for PostgreSQL.
-- Audit records are append-only by design (rules.md §7). This trigger makes
-- UPDATE/DELETE on the audit table a hard error at the database level, so the
-- "immutable" property survives code bugs.
CREATE OR REPLACE FUNCTION block_audit_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit records are immutable: UPDATE/DELETE is forbidden (scan_id=%, ts=%)',
        OLD.scan_id, OLD.created_at;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_no_update ON audit_log;
DROP TRIGGER IF EXISTS audit_no_delete ON audit_log;

CREATE TRIGGER audit_no_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION block_audit_mutation();

CREATE TRIGGER audit_no_delete
    BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION block_audit_mutation();