ALTER TABLE "channel_keys" ADD COLUMN "confirmed_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "messages" ADD COLUMN "broadcast_mention" boolean;
