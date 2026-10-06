-- Registration proves the email address with a mailed code. One pending code
-- per address; only its keyed digest is stored.
CREATE TABLE "email_verifications" (
	"email" text PRIMARY KEY NOT NULL,
	"code_hash" text NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "email_verifications_attempts_check" CHECK ("email_verifications"."attempts" >= 0)
);
--> statement-breakpoint
CREATE INDEX "email_verifications_expires_idx" ON "email_verifications" USING btree ("expires_at");
