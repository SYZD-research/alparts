CREATE TABLE "workspace_invitations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"role_id" uuid,
	"token_hash" text NOT NULL,
	"email" text,
	"created_by" uuid NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"used_by" uuid,
	"revoked_at" timestamp with time zone,
	"revoked_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "workspace_invitations_token_hash_unique" UNIQUE("token_hash")
);
--> statement-breakpoint
ALTER TABLE "workspace_invitations" ADD CONSTRAINT "workspace_invitations_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "workspace_invitations" ADD CONSTRAINT "workspace_invitations_role_id_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."roles"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "workspace_invitations" ADD CONSTRAINT "workspace_invitations_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "workspace_invitations" ADD CONSTRAINT "workspace_invitations_used_by_users_id_fk" FOREIGN KEY ("used_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "workspace_invitations" ADD CONSTRAINT "workspace_invitations_revoked_by_users_id_fk" FOREIGN KEY ("revoked_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "workspace_invitations_workspace_created_idx" ON "workspace_invitations" USING btree ("workspace_id","created_at");--> statement-breakpoint
CREATE INDEX "workspace_invitations_expires_at_idx" ON "workspace_invitations" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "workspace_invitations_role_id_idx" ON "workspace_invitations" USING btree ("role_id");--> statement-breakpoint
-- Earlier Phase 1 workspaces placed every non-administrator role at position
-- 50. Preserve any later/manual customization by updating only that legacy
-- value while establishing a usable standard hierarchy for management APIs.
UPDATE "roles" SET "position" = 80 WHERE "name" = 'SecurityManager' AND "position" = 50;--> statement-breakpoint
UPDATE "roles" SET "position" = 20 WHERE "name" IN ('Guest', 'Integration') AND "position" = 50;
