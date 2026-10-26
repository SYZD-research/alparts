-- Fresh start rule (c) counts the removal of a member whose user no longer
-- sees the channel from when that user lost it. The group-wide
-- remove_required_at kept the first loss while any such member remained, so
-- a later loss could count from an earlier one that had since been undone
-- (R-057). Each member now keeps its own time.
ALTER TABLE "mls_group_members" ADD COLUMN "access_lost_at" timestamp with time zone;--> statement-breakpoint
-- Groups that were waiting for such a removal did not record whose loss came
-- when, so their current members count from now: rule (c) can only wait
-- longer. A member whose user still sees the channel gets a new time when the
-- user loses it.
UPDATE "mls_group_members" AS "m" SET "access_lost_at" = now()
FROM "mls_groups" AS "g"
WHERE "g"."channel_id" = "m"."channel_id" AND "g"."remove_required_at" IS NOT NULL AND "m"."removed_version" IS NULL;--> statement-breakpoint
ALTER TABLE "mls_groups" DROP COLUMN "remove_required_at";
