ALTER TABLE "attachments" ADD COLUMN "channel_id" uuid;--> statement-breakpoint
ALTER TABLE "attachments" ADD COLUMN "signer_device_id" uuid;--> statement-breakpoint
ALTER TABLE "attachments" ADD COLUMN "key_version" integer;--> statement-breakpoint
ALTER TABLE "attachments" ADD COLUMN "signature" text;--> statement-breakpoint
UPDATE "attachments" AS "a"
SET "channel_id" = "m"."channel_id", "key_version" = "m"."key_version"
FROM "messages" AS "m"
WHERE "m"."id" = "a"."message_id";--> statement-breakpoint
ALTER TABLE "attachments" ALTER COLUMN "channel_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "attachments" ALTER COLUMN "key_version" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "attachments" ADD CONSTRAINT "attachments_channel_id_channels_id_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."channels"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attachments" ADD CONSTRAINT "attachments_signer_device_id_devices_id_fk" FOREIGN KEY ("signer_device_id") REFERENCES "public"."devices"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "attachments_channel_id_idx" ON "attachments" USING btree ("channel_id");--> statement-breakpoint
CREATE INDEX "attachments_signer_device_id_idx" ON "attachments" USING btree ("signer_device_id");--> statement-breakpoint
ALTER TABLE "attachments" ADD CONSTRAINT "attachments_key_version_check" CHECK ("attachments"."key_version" >= 1);--> statement-breakpoint
ALTER TABLE "attachments" ADD CONSTRAINT "attachments_signature_pair_check" CHECK (("attachments"."signer_device_id" is null and "attachments"."signature" is null) or ("attachments"."signer_device_id" is not null and "attachments"."signature" is not null));
