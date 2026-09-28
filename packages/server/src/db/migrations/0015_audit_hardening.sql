-- Outstanding grants must be re-issued with their authentication snapshot.
DELETE FROM step_up_grants;
--> statement-breakpoint
ALTER TABLE step_up_grants ADD COLUMN authentication jsonb NOT NULL;
--> statement-breakpoint
-- Old recovery codes require an approved device to enroll the retrieval capability.
ALTER TABLE history_recovery ADD COLUMN access_token_hash text;
