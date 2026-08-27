ALTER TABLE "devices" ADD CONSTRAINT "devices_id_user_id_unique" UNIQUE("id", "user_id");--> statement-breakpoint
ALTER TABLE "channel_key_epochs" ADD COLUMN "protocol_version" integer DEFAULT 2 NOT NULL;--> statement-breakpoint
ALTER TABLE "channel_key_epochs" ADD COLUMN "status" text DEFAULT 'pending' NOT NULL;--> statement-breakpoint
ALTER TABLE "channel_key_epochs" ADD COLUMN "activated_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "channel_key_epochs" ADD COLUMN "aborted_at" timestamp with time zone;--> statement-breakpoint
UPDATE "channel_key_epochs"
SET
	"protocol_version" = 1,
	"status" = 'retired';--> statement-breakpoint
UPDATE "channels" AS "c"
SET "key_rotation_required" = true
WHERE EXISTS (
	SELECT 1
	FROM "channel_key_epochs" AS "e"
	WHERE "e"."channel_id" = "c"."id"
);--> statement-breakpoint
ALTER TABLE "channel_key_epochs" ADD CONSTRAINT "channel_key_epochs_protocol_version_check" CHECK ("channel_key_epochs"."protocol_version" >= 1);--> statement-breakpoint
ALTER TABLE "channel_key_epochs" ADD CONSTRAINT "channel_key_epochs_status_check" CHECK ("channel_key_epochs"."status" IN ('pending', 'active', 'retired', 'aborted'));--> statement-breakpoint
ALTER TABLE "channel_key_epochs" ADD CONSTRAINT "channel_key_epochs_status_timestamps_check" CHECK (
	("channel_key_epochs"."status" = 'pending' AND "channel_key_epochs"."activated_at" IS NULL AND "channel_key_epochs"."aborted_at" IS NULL)
	OR ("channel_key_epochs"."status" = 'active' AND "channel_key_epochs"."activated_at" IS NOT NULL AND "channel_key_epochs"."aborted_at" IS NULL)
	OR ("channel_key_epochs"."status" = 'retired' AND "channel_key_epochs"."aborted_at" IS NULL)
	OR ("channel_key_epochs"."status" = 'aborted' AND "channel_key_epochs"."activated_at" IS NULL AND "channel_key_epochs"."aborted_at" IS NOT NULL)
);--> statement-breakpoint
CREATE UNIQUE INDEX "channel_key_epochs_one_pending_per_channel_idx" ON "channel_key_epochs" USING btree ("channel_id") WHERE "status" = 'pending';--> statement-breakpoint
CREATE UNIQUE INDEX "channel_key_epochs_one_active_per_channel_idx" ON "channel_key_epochs" USING btree ("channel_id") WHERE "status" = 'active';--> statement-breakpoint
ALTER TABLE "channel_keys" DROP CONSTRAINT "channel_keys_channel_id_version_device_id_unique";--> statement-breakpoint
ALTER TABLE "channel_keys" ADD CONSTRAINT "channel_keys_recipient_distributor_unique" UNIQUE NULLS NOT DISTINCT("channel_id", "version", "device_id", "distributor_device_id");--> statement-breakpoint
ALTER TABLE "channel_keys" ADD CONSTRAINT "channel_keys_recipient_delivery_unique" UNIQUE("channel_id", "version", "device_id", "id");--> statement-breakpoint
CREATE TABLE "channel_key_epoch_recipients" (
	"channel_id" uuid NOT NULL,
	"version" integer NOT NULL,
	"device_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"required_for_activation" boolean DEFAULT true NOT NULL,
	"accepted_delivery_id" uuid,
	"acknowledgement_signature" text,
	"acknowledged_at" timestamp with time zone,
	CONSTRAINT "channel_key_epoch_recipients_channel_id_version_device_id_pk" PRIMARY KEY("channel_id", "version", "device_id"),
	CONSTRAINT "channel_key_epoch_recipients_acknowledgement_check" CHECK (
		("accepted_delivery_id" IS NULL AND "acknowledgement_signature" IS NULL AND "acknowledged_at" IS NULL)
		OR ("accepted_delivery_id" IS NOT NULL AND "acknowledgement_signature" IS NOT NULL AND "acknowledged_at" IS NOT NULL)
	)
);--> statement-breakpoint
ALTER TABLE "channel_key_epoch_recipients" ADD CONSTRAINT "channel_key_epoch_recipients_epoch_fk" FOREIGN KEY ("channel_id", "version") REFERENCES "public"."channel_key_epochs"("channel_id", "version") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "channel_key_epoch_recipients" ADD CONSTRAINT "channel_key_epoch_recipients_device_id_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."devices"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "channel_key_epoch_recipients" ADD CONSTRAINT "channel_key_epoch_recipients_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "channel_key_epoch_recipients" ADD CONSTRAINT "channel_key_epoch_recipients_device_user_fk" FOREIGN KEY ("device_id", "user_id") REFERENCES "public"."devices"("id", "user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "channel_key_epoch_recipients" ADD CONSTRAINT "channel_key_epoch_recipients_accepted_delivery_fk" FOREIGN KEY ("channel_id", "version", "device_id", "accepted_delivery_id") REFERENCES "public"."channel_keys"("channel_id", "version", "device_id", "id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "channel_key_epoch_recipients_epoch_idx" ON "channel_key_epoch_recipients" USING btree ("channel_id", "version");--> statement-breakpoint
CREATE INDEX "channel_key_epoch_recipients_device_id_idx" ON "channel_key_epoch_recipients" USING btree ("device_id");--> statement-breakpoint
CREATE INDEX "channel_key_epoch_recipients_user_id_idx" ON "channel_key_epoch_recipients" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "channel_key_epoch_recipients_accepted_delivery_id_idx" ON "channel_key_epoch_recipients" USING btree ("accepted_delivery_id");--> statement-breakpoint
INSERT INTO "channel_key_epoch_recipients" (
	"channel_id",
	"version",
	"device_id",
	"user_id",
	"required_for_activation"
)
SELECT
	"ck"."channel_id",
	"ck"."version",
	"ck"."device_id",
	"d"."user_id",
	true
FROM "channel_keys" AS "ck"
INNER JOIN "channel_key_epochs" AS "e"
	ON "e"."channel_id" = "ck"."channel_id"
	AND "e"."version" = "ck"."version"
INNER JOIN "devices" AS "d"
	ON "d"."id" = "ck"."device_id"
ON CONFLICT ("channel_id", "version", "device_id") DO NOTHING;--> statement-breakpoint
ALTER TABLE "channel_keys" ADD CONSTRAINT "channel_keys_epoch_recipient_fk" FOREIGN KEY ("channel_id", "version", "device_id") REFERENCES "public"."channel_key_epoch_recipients"("channel_id", "version", "device_id") ON DELETE no action ON UPDATE no action NOT VALID;--> statement-breakpoint
DO $$
BEGIN
	IF NOT EXISTS (
		SELECT 1
		FROM "channel_keys" AS "ck"
		LEFT JOIN "channel_key_epoch_recipients" AS "r"
			ON "r"."channel_id" = "ck"."channel_id"
			AND "r"."version" = "ck"."version"
			AND "r"."device_id" = "ck"."device_id"
		WHERE "r"."device_id" IS NULL
	) THEN
		ALTER TABLE "channel_keys" VALIDATE CONSTRAINT "channel_keys_epoch_recipient_fk";
	END IF;
END
$$;
