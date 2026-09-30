-- Forum channels. Posts are messages in the forum channel, encrypted with its
-- channel key; forum_posts keeps the listing and moderation state the server
-- already observes (author, times, reply count) so listing never decrypts.
-- messages.post_id is covered by the signed v4 envelope.
CREATE TABLE "forum_post_reads" (
	"user_id" uuid NOT NULL,
	"post_id" uuid NOT NULL,
	"last_read_activity_at" timestamp with time zone NOT NULL,
	CONSTRAINT "forum_post_reads_pk" PRIMARY KEY("user_id","post_id")
);
--> statement-breakpoint
CREATE TABLE "forum_post_tags" (
	"post_id" uuid NOT NULL,
	"channel_id" uuid NOT NULL,
	"tag_id" uuid NOT NULL,
	CONSTRAINT "forum_post_tags_pk" PRIMARY KEY("post_id","tag_id")
);
--> statement-breakpoint
CREATE TABLE "forum_posts" (
	"message_id" uuid PRIMARY KEY NOT NULL,
	"channel_id" uuid NOT NULL,
	"author_id" uuid NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"last_activity_at" timestamp with time zone NOT NULL,
	"reply_count" integer DEFAULT 0 NOT NULL,
	"locked_at" timestamp with time zone,
	"locked_by" uuid,
	"resolved_at" timestamp with time zone,
	"resolved_by" uuid,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "forum_posts_message_channel_unique" UNIQUE("message_id","channel_id"),
	CONSTRAINT "forum_posts_reply_count_check" CHECK ("forum_posts"."reply_count" >= 0),
	CONSTRAINT "forum_posts_activity_check" CHECK ("forum_posts"."last_activity_at" >= "forum_posts"."created_at"),
	CONSTRAINT "forum_posts_locked_pair_check" CHECK (("forum_posts"."locked_at" is null) = ("forum_posts"."locked_by" is null)),
	CONSTRAINT "forum_posts_resolved_pair_check" CHECK (("forum_posts"."resolved_at" is null) = ("forum_posts"."resolved_by" is null))
);
--> statement-breakpoint
CREATE TABLE "forum_tags" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"channel_id" uuid NOT NULL,
	"name" text NOT NULL,
	"position" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "forum_tags_channel_name_unique" UNIQUE("channel_id","name"),
	CONSTRAINT "forum_tags_channel_id_unique" UNIQUE("channel_id","id"),
	CONSTRAINT "forum_tags_name_check" CHECK (char_length("forum_tags"."name") between 1 and 20 and "forum_tags"."name" = btrim("forum_tags"."name")),
	CONSTRAINT "forum_tags_position_check" CHECK ("forum_tags"."position" between 0 and 1000000)
);
--> statement-breakpoint
ALTER TABLE "category_role_permission_overrides" DROP CONSTRAINT "category_role_permission_overrides_allow_mask_check";--> statement-breakpoint
ALTER TABLE "category_role_permission_overrides" DROP CONSTRAINT "category_role_permission_overrides_deny_mask_check";--> statement-breakpoint
ALTER TABLE "channel_role_permission_overrides" DROP CONSTRAINT "channel_role_permission_overrides_allow_mask_check";--> statement-breakpoint
ALTER TABLE "channel_role_permission_overrides" DROP CONSTRAINT "channel_role_permission_overrides_deny_mask_check";--> statement-breakpoint
ALTER TABLE "messages" ADD COLUMN "post_id" uuid;--> statement-breakpoint
ALTER TABLE "forum_post_reads" ADD CONSTRAINT "forum_post_reads_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forum_post_reads" ADD CONSTRAINT "forum_post_reads_post_id_forum_posts_message_id_fk" FOREIGN KEY ("post_id") REFERENCES "public"."forum_posts"("message_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forum_post_tags" ADD CONSTRAINT "forum_post_tags_post_fk" FOREIGN KEY ("post_id","channel_id") REFERENCES "public"."forum_posts"("message_id","channel_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forum_post_tags" ADD CONSTRAINT "forum_post_tags_tag_fk" FOREIGN KEY ("channel_id","tag_id") REFERENCES "public"."forum_tags"("channel_id","id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forum_posts" ADD CONSTRAINT "forum_posts_message_id_messages_id_fk" FOREIGN KEY ("message_id") REFERENCES "public"."messages"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forum_posts" ADD CONSTRAINT "forum_posts_channel_id_channels_id_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."channels"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forum_posts" ADD CONSTRAINT "forum_posts_author_id_users_id_fk" FOREIGN KEY ("author_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forum_posts" ADD CONSTRAINT "forum_posts_locked_by_users_id_fk" FOREIGN KEY ("locked_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forum_posts" ADD CONSTRAINT "forum_posts_resolved_by_users_id_fk" FOREIGN KEY ("resolved_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forum_tags" ADD CONSTRAINT "forum_tags_channel_id_channels_id_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."channels"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "forum_post_reads_post_idx" ON "forum_post_reads" USING btree ("post_id");--> statement-breakpoint
CREATE INDEX "forum_post_tags_tag_idx" ON "forum_post_tags" USING btree ("channel_id","tag_id");--> statement-breakpoint
CREATE INDEX "forum_posts_channel_activity_idx" ON "forum_posts" USING btree ("channel_id","last_activity_at" DESC NULLS LAST,"message_id" DESC NULLS LAST) WHERE "forum_posts"."deleted_at" is null;--> statement-breakpoint
CREATE INDEX "forum_posts_channel_created_idx" ON "forum_posts" USING btree ("channel_id","created_at" DESC NULLS LAST,"message_id" DESC NULLS LAST) WHERE "forum_posts"."deleted_at" is null;--> statement-breakpoint
CREATE INDEX "forum_posts_author_idx" ON "forum_posts" USING btree ("author_id");--> statement-breakpoint
CREATE INDEX "forum_tags_channel_position_idx" ON "forum_tags" USING btree ("channel_id","position");--> statement-breakpoint
ALTER TABLE "messages" ADD CONSTRAINT "messages_post_id_fk" FOREIGN KEY ("post_id") REFERENCES "public"."messages"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "messages_post_created_idx" ON "messages" USING btree ("post_id","created_at","id") WHERE "messages"."post_id" is not null;--> statement-breakpoint
ALTER TABLE "category_role_permission_overrides" ADD CONSTRAINT "category_role_permission_overrides_allow_mask_check" CHECK ("category_role_permission_overrides"."allow_mask" >= 0 and ("category_role_permission_overrides"."allow_mask" & -409728) = 0);--> statement-breakpoint
ALTER TABLE "category_role_permission_overrides" ADD CONSTRAINT "category_role_permission_overrides_deny_mask_check" CHECK ("category_role_permission_overrides"."deny_mask" >= 0 and ("category_role_permission_overrides"."deny_mask" & -409728) = 0);--> statement-breakpoint
ALTER TABLE "channel_role_permission_overrides" ADD CONSTRAINT "channel_role_permission_overrides_allow_mask_check" CHECK ("channel_role_permission_overrides"."allow_mask" >= 0 and ("channel_role_permission_overrides"."allow_mask" & -409728) = 0);--> statement-breakpoint
ALTER TABLE "channel_role_permission_overrides" ADD CONSTRAINT "channel_role_permission_overrides_deny_mask_check" CHECK ("channel_role_permission_overrides"."deny_mask" >= 0 and ("channel_role_permission_overrides"."deny_mask" & -409728) = 0);
--> statement-breakpoint
-- CREATE_POSTS (bit 18) starts as a copy of SEND_MESSAGES (bit 0) everywhere,
-- so nobody gains or loses the ability to write anywhere by this migration.
UPDATE "roles" SET "permissions" = "permissions" | 262144 WHERE ("permissions" & 1) = 1;
--> statement-breakpoint
UPDATE "category_role_permission_overrides" SET
  "allow_mask" = CASE WHEN ("allow_mask" & 1) = 1 THEN "allow_mask" | 262144 ELSE "allow_mask" END,
  "deny_mask" = CASE WHEN ("deny_mask" & 1) = 1 THEN "deny_mask" | 262144 ELSE "deny_mask" END,
  "revision" = "revision" + 1,
  "updated_at" = now()
WHERE (("allow_mask" | "deny_mask") & 1) = 1;
--> statement-breakpoint
UPDATE "channel_role_permission_overrides" SET
  "allow_mask" = CASE WHEN ("allow_mask" & 1) = 1 THEN "allow_mask" | 262144 ELSE "allow_mask" END,
  "deny_mask" = CASE WHEN ("deny_mask" & 1) = 1 THEN "deny_mask" | 262144 ELSE "deny_mask" END,
  "revision" = "revision" + 1,
  "updated_at" = now()
WHERE (("allow_mask" | "deny_mask") & 1) = 1;
