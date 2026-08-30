-- Supporting indexes for transactionally enforced tenant quotas. These are
-- additive and rollback-safe. On a large pre-existing deployment, create the
-- same indexes CONCURRENTLY in a separately approved expand phase before
-- applying this migration to avoid a long write lock.
ALTER TABLE "dm_conversations" ADD COLUMN "created_by" uuid;--> statement-breakpoint
ALTER TABLE "dm_conversations" ADD CONSTRAINT "dm_conversations_created_by_users_id_fk"
  FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
DO $quota_preflight$
BEGIN
  IF EXISTS (SELECT 1 FROM "workspaces" GROUP BY "owner_id" HAVING count(*) > 20) THEN
    RAISE EXCEPTION 'quota preflight: an owner has more than 20 workspaces';
  END IF;
  IF EXISTS (SELECT 1 FROM "workspace_members" GROUP BY "user_id" HAVING count(*) > 50) THEN
    RAISE EXCEPTION 'quota preflight: a user has more than 50 workspace memberships';
  END IF;
  IF EXISTS (SELECT 1 FROM "workspace_members" GROUP BY "workspace_id" HAVING count(*) > 50) THEN
    RAISE EXCEPTION 'quota preflight: a workspace has more than 50 members';
  END IF;
  IF EXISTS (SELECT 1 FROM "roles" GROUP BY "workspace_id" HAVING count(*) > 32) THEN
    RAISE EXCEPTION 'quota preflight: a workspace has more than 32 roles';
  END IF;
  IF EXISTS (SELECT 1 FROM "categories" GROUP BY "workspace_id" HAVING count(*) > 50) THEN
    RAISE EXCEPTION 'quota preflight: a workspace has more than 50 categories';
  END IF;
  IF EXISTS (SELECT 1 FROM "member_roles" GROUP BY "member_id" HAVING count(*) > 16) THEN
    RAISE EXCEPTION 'quota preflight: a member has more than 16 role assignments';
  END IF;
  IF EXISTS (
    SELECT 1 FROM "channels" WHERE "type" <> 'dm'
    GROUP BY "workspace_id" HAVING count(*) > 100
  ) THEN
    RAISE EXCEPTION 'quota preflight: a workspace has more than 100 non-DM channels';
  END IF;
  IF EXISTS (
    SELECT 1 FROM "channels" WHERE "type" = 'dm'
    GROUP BY "workspace_id" HAVING count(*) > 200
  ) THEN
    RAISE EXCEPTION 'quota preflight: a workspace has more than 200 DM channels';
  END IF;
  IF EXISTS (SELECT 1 FROM "workspace_invitations" GROUP BY "workspace_id" HAVING count(*) > 1000) THEN
    RAISE EXCEPTION 'quota preflight: a workspace retains more than 1000 invitations';
  END IF;
  IF EXISTS (
    SELECT 1 FROM "workspace_invitations"
    WHERE "used_at" IS NULL AND "revoked_at" IS NULL AND "expires_at" > now()
    GROUP BY "workspace_id" HAVING count(*) > 100
  ) THEN
    RAISE EXCEPTION 'quota preflight: a workspace has more than 100 active invitations';
  END IF;
  IF EXISTS (SELECT 1 FROM "message_bookmarks" GROUP BY "user_id" HAVING count(*) > 1000) THEN
    RAISE EXCEPTION 'quota preflight: a user has more than 1000 bookmarks';
  END IF;
  IF EXISTS (
    SELECT 1 FROM "devices" WHERE "revoked_at" IS NULL
    GROUP BY "user_id" HAVING count(*) > 8
  ) THEN
    RAISE EXCEPTION 'quota preflight: a user has more than 8 active devices';
  END IF;
  IF EXISTS (
    SELECT 1 FROM "sessions" WHERE "expires_at" > now()
    GROUP BY "user_id" HAVING count(*) > 16
  ) THEN
    RAISE EXCEPTION 'quota preflight: a user has more than 16 active sessions';
  END IF;
  IF EXISTS (SELECT 1 FROM "message_pins" GROUP BY "channel_id" HAVING count(*) > 1000) THEN
    RAISE EXCEPTION 'quota preflight: a channel has more than 1000 pins';
  END IF;
  IF EXISTS (SELECT 1 FROM "message_reactions" GROUP BY "message_id" HAVING count(*) > 1000) THEN
    RAISE EXCEPTION 'quota preflight: a message has more than 1000 reactions';
  END IF;
  IF EXISTS (
    SELECT 1 FROM "attachment_uploads"
    WHERE "completed_at" IS NULL AND "expires_at" > now()
    GROUP BY "uploader_id" HAVING count(*) > 16
  ) THEN
    RAISE EXCEPTION 'quota preflight: a user has more than 16 pending uploads';
  END IF;
  IF EXISTS (
    SELECT 1 FROM "attachment_uploads" AS au
    INNER JOIN "messages" AS m ON m."id" = au."message_id"
    INNER JOIN "channels" AS c ON c."id" = m."channel_id"
    WHERE au."completed_at" IS NULL AND au."expires_at" > now()
    GROUP BY c."workspace_id" HAVING count(*) > 200
  ) THEN
    RAISE EXCEPTION 'quota preflight: a workspace has more than 200 pending uploads';
  END IF;
END
$quota_preflight$;--> statement-breakpoint
CREATE INDEX "workspaces_owner_id_idx" ON "workspaces" USING btree ("owner_id");--> statement-breakpoint
CREATE INDEX "channels_workspace_type_idx" ON "channels" USING btree ("workspace_id", "type");--> statement-breakpoint
CREATE INDEX "message_bookmarks_user_created_idx" ON "message_bookmarks" USING btree ("user_id", "created_at", "message_id");--> statement-breakpoint
CREATE INDEX "sessions_user_expires_idx" ON "sessions" USING btree ("user_id", "expires_at");--> statement-breakpoint
CREATE INDEX "attachment_uploads_uploader_expiry_idx" ON "attachment_uploads" USING btree ("uploader_id", "expires_at");--> statement-breakpoint
CREATE INDEX "dm_conversations_created_by_idx" ON "dm_conversations" USING btree ("created_by");
