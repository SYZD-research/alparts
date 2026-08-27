CREATE TABLE "channel_preferences" (
	"user_id" uuid NOT NULL,
	"channel_id" uuid NOT NULL,
	"favorite" boolean DEFAULT false NOT NULL,
	"muted" boolean DEFAULT false NOT NULL,
	"hidden" boolean DEFAULT false NOT NULL,
	"notification_level" text DEFAULT 'all' NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "channel_preferences_user_id_channel_id_pk" PRIMARY KEY("user_id","channel_id")
);
--> statement-breakpoint
CREATE TABLE "message_bookmarks" (
	"user_id" uuid NOT NULL,
	"message_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "message_bookmarks_user_id_message_id_pk" PRIMARY KEY("user_id","message_id")
);
--> statement-breakpoint
ALTER TABLE "channel_preferences" ADD CONSTRAINT "channel_preferences_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "channel_preferences" ADD CONSTRAINT "channel_preferences_channel_id_channels_id_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."channels"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "message_bookmarks" ADD CONSTRAINT "message_bookmarks_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "message_bookmarks" ADD CONSTRAINT "message_bookmarks_message_id_messages_id_fk" FOREIGN KEY ("message_id") REFERENCES "public"."messages"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "channel_preferences_channel_id_idx" ON "channel_preferences" USING btree ("channel_id");--> statement-breakpoint
CREATE INDEX "message_bookmarks_message_id_idx" ON "message_bookmarks" USING btree ("message_id");