ALTER TABLE "channel_keys" ADD COLUMN "distributor_device_id" uuid;--> statement-breakpoint
ALTER TABLE "channel_keys" ADD COLUMN "signature" text;--> statement-breakpoint
ALTER TABLE "channel_keys" ADD CONSTRAINT "channel_keys_distributor_device_id_devices_id_fk" FOREIGN KEY ("distributor_device_id") REFERENCES "public"."devices"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "channel_keys_distributor_device_id_idx" ON "channel_keys" USING btree ("distributor_device_id");--> statement-breakpoint
ALTER TABLE "channel_keys" ADD CONSTRAINT "channel_keys_signature_pair_check" CHECK (("channel_keys"."distributor_device_id" is null and "channel_keys"."signature" is null) or ("channel_keys"."distributor_device_id" is not null and "channel_keys"."signature" is not null));--> statement-breakpoint
CREATE TABLE "channel_key_epochs" (
	"channel_id" uuid NOT NULL,
	"version" integer NOT NULL,
	"key_commitment" text NOT NULL,
	"distributor_device_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "channel_key_epochs_channel_id_version_pk" PRIMARY KEY("channel_id","version"),
	CONSTRAINT "channel_key_epochs_version_check" CHECK ("channel_key_epochs"."version" >= 1),
	CONSTRAINT "channel_key_epochs_commitment_check" CHECK ("channel_key_epochs"."key_commitment" ~ '^[A-Za-z0-9_-]{43}$')
);--> statement-breakpoint
ALTER TABLE "channel_key_epochs" ADD CONSTRAINT "channel_key_epochs_channel_id_channels_id_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."channels"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "channel_key_epochs" ADD CONSTRAINT "channel_key_epochs_distributor_device_id_devices_id_fk" FOREIGN KEY ("distributor_device_id") REFERENCES "public"."devices"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "channel_key_epochs_distributor_device_id_idx" ON "channel_key_epochs" USING btree ("distributor_device_id");--> statement-breakpoint
UPDATE "channels" AS "c"
SET "key_rotation_required" = true
WHERE EXISTS (SELECT 1 FROM "channel_keys" AS "ck" WHERE "ck"."channel_id" = "c"."id");
