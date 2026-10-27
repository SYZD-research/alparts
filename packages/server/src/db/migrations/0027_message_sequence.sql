-- Message protocol v6 numbers each device's events in a channel and lets an
-- event name the newest events of other devices it was written after, and an
-- edit the version it replaces. The server refuses a number a device already
-- used, so clients can tell when an event was withheld or moved (R-058).
-- Older events keep null in all three columns.
ALTER TABLE "messages" ADD COLUMN "device_seq" integer;--> statement-breakpoint
ALTER TABLE "messages" ADD COLUMN "seen_heads" jsonb;--> statement-breakpoint
ALTER TABLE "messages" ADD COLUMN "supersedes" text;--> statement-breakpoint
ALTER TABLE "messages" ADD CONSTRAINT "messages_channel_device_seq_unique" UNIQUE("channel_id","device_id","device_seq");--> statement-breakpoint
ALTER TABLE "messages" ADD CONSTRAINT "messages_device_seq_check" CHECK ("messages"."device_seq" is null or ("messages"."device_seq" > 0 and "messages"."device_id" is not null and "messages"."seen_heads" is not null));