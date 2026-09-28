ALTER TABLE "category_role_permission_overrides" DROP CONSTRAINT "category_role_permission_overrides_allow_mask_check";
--> statement-breakpoint
ALTER TABLE "category_role_permission_overrides" ADD CONSTRAINT "category_role_permission_overrides_allow_mask_check" CHECK ("allow_mask" >= 0 AND ("allow_mask" & -147584) = 0);
--> statement-breakpoint
ALTER TABLE "category_role_permission_overrides" DROP CONSTRAINT "category_role_permission_overrides_deny_mask_check";
--> statement-breakpoint
ALTER TABLE "category_role_permission_overrides" ADD CONSTRAINT "category_role_permission_overrides_deny_mask_check" CHECK ("deny_mask" >= 0 AND ("deny_mask" & -147584) = 0);
--> statement-breakpoint
ALTER TABLE "channel_role_permission_overrides" DROP CONSTRAINT "channel_role_permission_overrides_allow_mask_check";
--> statement-breakpoint
ALTER TABLE "channel_role_permission_overrides" ADD CONSTRAINT "channel_role_permission_overrides_allow_mask_check" CHECK ("allow_mask" >= 0 AND ("allow_mask" & -147584) = 0);
--> statement-breakpoint
ALTER TABLE "channel_role_permission_overrides" DROP CONSTRAINT "channel_role_permission_overrides_deny_mask_check";
--> statement-breakpoint
ALTER TABLE "channel_role_permission_overrides" ADD CONSTRAINT "channel_role_permission_overrides_deny_mask_check" CHECK ("deny_mask" >= 0 AND ("deny_mask" & -147584) = 0);
--> statement-breakpoint
UPDATE roles SET permissions = permissions | 131072 WHERE name IN ('Owner', 'Administrator', 'Member');
--> statement-breakpoint
UPDATE users SET email = normalize(lower(btrim(email)), NFC);
--> statement-breakpoint
UPDATE workspace_invitations SET email = normalize(lower(btrim(email)), NFC) WHERE email IS NOT NULL;
--> statement-breakpoint
CREATE TABLE channel_directory_heads (
  channel_id uuid NOT NULL REFERENCES channels(id),
  user_id uuid NOT NULL REFERENCES users(id),
  sequence integer NOT NULL,
  PRIMARY KEY (channel_id, user_id),
  CONSTRAINT channel_directory_heads_sequence_check CHECK (sequence between 0 and 8192)
);
--> statement-breakpoint
INSERT INTO channel_directory_heads (channel_id, user_id, sequence)
SELECT e.channel_id, (h->>'userId')::uuid, max((h->>'sequence')::integer)
FROM mls_epochs e, jsonb_array_elements(e.envelope->'directoryHeads') h
GROUP BY e.channel_id, (h->>'userId')::uuid;
