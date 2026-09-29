-- Row triggers do not fire for TRUNCATE; guard the statement as well.
CREATE TRIGGER device_directory_no_truncate BEFORE TRUNCATE ON device_directory_events
FOR EACH STATEMENT EXECUTE FUNCTION reject_directory_rewrite();
--> statement-breakpoint
CREATE FUNCTION reject_audit_rewrite() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit log is append-only'; END $$;
--> statement-breakpoint
CREATE TRIGGER audit_logs_no_rewrite BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION reject_audit_rewrite();
--> statement-breakpoint
CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs
FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_rewrite();
--> statement-breakpoint
CREATE INDEX "authentication_challenges_session_idx" ON "authentication_challenges" USING btree ("session_id");
