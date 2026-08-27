CREATE TABLE "message_reactions" (
	"message_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"emoji" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "message_reactions_message_id_user_id_emoji_pk" PRIMARY KEY("message_id","user_id","emoji")
);--> statement-breakpoint
ALTER TABLE "message_reactions" ADD CONSTRAINT "message_reactions_message_id_messages_id_fk" FOREIGN KEY ("message_id") REFERENCES "public"."messages"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "message_reactions" ADD CONSTRAINT "message_reactions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "message_reactions_message_id_idx" ON "message_reactions" USING btree ("message_id");--> statement-breakpoint
INSERT INTO "message_reactions" ("message_id", "user_id", "emoji", "created_at")
SELECT "ref_message_id", "author_id", "content", "created_at"
FROM (
	SELECT DISTINCT ON ("ref_message_id", "author_id", "content")
		"ref_message_id", "author_id", "content", "reaction_action", "created_at", "id"
	FROM "messages"
	WHERE "type" = 'reaction' AND "ref_message_id" IS NOT NULL
	ORDER BY "ref_message_id", "author_id", "content", "created_at" DESC, "id" DESC
) AS "latest"
WHERE "reaction_action" IS DISTINCT FROM 'remove';--> statement-breakpoint
DELETE FROM "messages" WHERE "type" = 'reaction';
