ALTER TABLE "sessions" ADD COLUMN "passkey_id" text;--> statement-breakpoint
CREATE INDEX "sessions_passkey_id_idx" ON "sessions" USING btree ("passkey_id") WHERE "sessions"."passkey_id" is not null;