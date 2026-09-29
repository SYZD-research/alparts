-- User profiles: editable bio and avatar. Avatar bytes live in object storage;
-- only the server-generated key and the public path are stored here.
ALTER TABLE "users" ADD COLUMN "bio" text;
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "avatar_object_key" text;
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "profile_updated_at" timestamp with time zone;
--> statement-breakpoint
-- Each account may ask a workspace to lift a profile warning once, ever.
ALTER TABLE "users" ADD COLUMN "flag_appeal_used_at" timestamp with time zone;
--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_bio_length_check" CHECK ("bio" IS NULL OR char_length("bio") <= 200);
--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_avatar_key_check" CHECK ("avatar_object_key" IS NULL OR "avatar_object_key" ~ '^avatars/v1/[0-9a-f-]{36}/[0-9a-f-]{36}$');
--> statement-breakpoint
CREATE TABLE "profile_flags" (
  "workspace_id" uuid NOT NULL REFERENCES "workspaces"("id"),
  "user_id" uuid NOT NULL REFERENCES "users"("id"),
  "flagged_by" uuid NOT NULL REFERENCES "users"("id"),
  "flagged_at" timestamp with time zone DEFAULT now() NOT NULL,
  "appeal_status" text DEFAULT 'none' NOT NULL,
  "appeal_requested_at" timestamp with time zone,
  CONSTRAINT "profile_flags_pk" PRIMARY KEY ("workspace_id", "user_id"),
  CONSTRAINT "profile_flags_appeal_status_check" CHECK ("appeal_status" IN ('none', 'pending', 'denied')),
  CONSTRAINT "profile_flags_appeal_time_check" CHECK (("appeal_status" = 'none') = ("appeal_requested_at" IS NULL))
);
--> statement-breakpoint
CREATE INDEX "profile_flags_user_idx" ON "profile_flags" USING btree ("user_id");
