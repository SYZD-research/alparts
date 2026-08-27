CREATE TABLE "category_role_permission_overrides" (
	"workspace_id" uuid NOT NULL,
	"category_id" uuid NOT NULL,
	"role_id" uuid NOT NULL,
	"allow_mask" integer DEFAULT 0 NOT NULL,
	"deny_mask" integer DEFAULT 0 NOT NULL,
	"revision" integer DEFAULT 1 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "category_role_permission_overrides_workspace_id_category_id_role_id_pk" PRIMARY KEY("workspace_id","category_id","role_id"),
	CONSTRAINT "category_role_permission_overrides_allow_mask_check" CHECK ("category_role_permission_overrides"."allow_mask" >= 0 and ("category_role_permission_overrides"."allow_mask" & -16512) = 0),
	CONSTRAINT "category_role_permission_overrides_deny_mask_check" CHECK ("category_role_permission_overrides"."deny_mask" >= 0 and ("category_role_permission_overrides"."deny_mask" & -16512) = 0),
	CONSTRAINT "category_role_permission_overrides_revision_check" CHECK ("category_role_permission_overrides"."revision" >= 1)
);
--> statement-breakpoint
CREATE TABLE "channel_role_permission_overrides" (
	"workspace_id" uuid NOT NULL,
	"channel_id" uuid NOT NULL,
	"role_id" uuid NOT NULL,
	"allow_mask" integer DEFAULT 0 NOT NULL,
	"deny_mask" integer DEFAULT 0 NOT NULL,
	"revision" integer DEFAULT 1 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "channel_role_permission_overrides_workspace_id_channel_id_role_id_pk" PRIMARY KEY("workspace_id","channel_id","role_id"),
	CONSTRAINT "channel_role_permission_overrides_allow_mask_check" CHECK ("channel_role_permission_overrides"."allow_mask" >= 0 and ("channel_role_permission_overrides"."allow_mask" & -16512) = 0),
	CONSTRAINT "channel_role_permission_overrides_deny_mask_check" CHECK ("channel_role_permission_overrides"."deny_mask" >= 0 and ("channel_role_permission_overrides"."deny_mask" & -16512) = 0),
	CONSTRAINT "channel_role_permission_overrides_revision_check" CHECK ("channel_role_permission_overrides"."revision" >= 1)
);
--> statement-breakpoint
ALTER TABLE "messages" ADD COLUMN "reaction_action" text;--> statement-breakpoint
ALTER TABLE "categories" ADD CONSTRAINT "categories_workspace_id_unique" UNIQUE("workspace_id","id");--> statement-breakpoint
ALTER TABLE "channels" ADD CONSTRAINT "channels_workspace_id_unique" UNIQUE("workspace_id","id");--> statement-breakpoint
ALTER TABLE "roles" ADD CONSTRAINT "roles_workspace_id_unique" UNIQUE("workspace_id","id");--> statement-breakpoint
ALTER TABLE "category_role_permission_overrides" ADD CONSTRAINT "category_role_permission_overrides_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "category_role_permission_overrides" ADD CONSTRAINT "category_role_overrides_category_workspace_fk" FOREIGN KEY ("workspace_id","category_id") REFERENCES "public"."categories"("workspace_id","id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "category_role_permission_overrides" ADD CONSTRAINT "category_role_overrides_role_workspace_fk" FOREIGN KEY ("workspace_id","role_id") REFERENCES "public"."roles"("workspace_id","id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "channel_role_permission_overrides" ADD CONSTRAINT "channel_role_permission_overrides_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "channel_role_permission_overrides" ADD CONSTRAINT "channel_role_overrides_channel_workspace_fk" FOREIGN KEY ("workspace_id","channel_id") REFERENCES "public"."channels"("workspace_id","id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "channel_role_permission_overrides" ADD CONSTRAINT "channel_role_overrides_role_workspace_fk" FOREIGN KEY ("workspace_id","role_id") REFERENCES "public"."roles"("workspace_id","id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "category_role_permission_overrides_role_idx" ON "category_role_permission_overrides" USING btree ("workspace_id","role_id");--> statement-breakpoint
CREATE INDEX "category_role_permission_overrides_category_idx" ON "category_role_permission_overrides" USING btree ("category_id");--> statement-breakpoint
CREATE INDEX "channel_role_permission_overrides_role_idx" ON "channel_role_permission_overrides" USING btree ("workspace_id","role_id");--> statement-breakpoint
CREATE INDEX "channel_role_permission_overrides_channel_idx" ON "channel_role_permission_overrides" USING btree ("channel_id");
