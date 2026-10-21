CREATE TABLE "attachment_removals" (
	"storage_key" text PRIMARY KEY NOT NULL,
	"channel_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"size_bytes" bigint NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "attachment_removals" ADD CONSTRAINT "attachment_removals_channel_id_channels_id_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."channels"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attachment_removals" ADD CONSTRAINT "attachment_removals_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "attachment_removals_channel_id_idx" ON "attachment_removals" USING btree ("channel_id");--> statement-breakpoint
CREATE INDEX "attachment_removals_user_id_idx" ON "attachment_removals" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "attachment_removals_created_at_idx" ON "attachment_removals" USING btree ("created_at");--> statement-breakpoint
-- Messages deleted earlier kept their attachments, pins and bookmarks. Do what
-- a delete does now: queue the stored objects of the attachments for removal
-- (they stay counted against the quotas until they are gone), then drop the
-- attachments with their completed uploads and chunk registrations, the pins
-- and the bookmarks.
INSERT INTO attachment_removals (storage_key, channel_id, user_id, size_bytes)
SELECT attachment.storage_key, message.channel_id, message.author_id, attachment.size_bytes
FROM attachments AS attachment
JOIN messages AS message ON message.id = attachment.message_id
WHERE EXISTS (
  SELECT 1 FROM messages AS deletion
  WHERE deletion.ref_message_id = attachment.message_id AND deletion.type = 'delete'
);
DELETE FROM attachments AS attachment
WHERE EXISTS (
  SELECT 1 FROM messages AS deletion
  WHERE deletion.ref_message_id = attachment.message_id AND deletion.type = 'delete'
);
DELETE FROM attachment_uploads AS upload
WHERE upload.completed_at IS NOT NULL AND EXISTS (
  SELECT 1 FROM messages AS deletion
  WHERE deletion.ref_message_id = upload.message_id AND deletion.type = 'delete'
);
DELETE FROM message_pins AS pin
WHERE EXISTS (
  SELECT 1 FROM messages AS deletion
  WHERE deletion.ref_message_id = pin.message_id AND deletion.type = 'delete'
);
DELETE FROM message_bookmarks AS bookmark
WHERE EXISTS (
  SELECT 1 FROM messages AS deletion
  WHERE deletion.ref_message_id = bookmark.message_id AND deletion.type = 'delete'
);
