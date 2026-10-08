-- Group protocol 4: one continuing RFC 9420 group per channel. The server
-- orders commits (one per key version) and an accepted commit is active at
-- once; nothing waits for acknowledgements.
CREATE TABLE mls_groups (
  channel_id uuid PRIMARY KEY REFERENCES channels(id),
  -- The current group, named by its genesis version. NULL while a migrated
  -- channel waits for its first group.
  genesis_version integer,
  -- Last accepted commit that refreshed the group key with an UpdatePath.
  path_refreshed_at timestamp with time zone,
  -- First package published for a channel whose earlier epoch predates v4.
  genesis_requested_at timestamp with time zone,
  -- Since when a member's user has no longer seen the channel; cleared by
  -- the next accepted commit (which must remove it) or when access returns.
  remove_required_at timestamp with time zone,
  CONSTRAINT mls_groups_genesis_check CHECK ((genesis_version IS NULL) = (path_refreshed_at IS NULL)),
  CONSTRAINT mls_groups_genesis_version_check CHECK (genesis_version IS NULL OR genesis_version >= 1)
);
--> statement-breakpoint
CREATE TABLE mls_member_packages (
  channel_id uuid NOT NULL REFERENCES channels(id),
  device_id uuid NOT NULL REFERENCES devices(id),
  package_id uuid NOT NULL,
  -- Canonical encoding only, so the bytes inside a commit match exactly.
  key_package text NOT NULL,
  signature text NOT NULL,
  -- Public keys of the package, compared to keep every leaf key unique.
  init_key text NOT NULL,
  encryption_key text NOT NULL,
  signature_key text NOT NULL,
  not_before timestamp with time zone NOT NULL,
  not_after timestamp with time zone NOT NULL,
  rejoin boolean DEFAULT false NOT NULL,
  created_at timestamp with time zone DEFAULT now() NOT NULL,
  PRIMARY KEY (channel_id, device_id),
  CONSTRAINT mls_member_packages_package_id_unique UNIQUE (package_id),
  CONSTRAINT mls_member_packages_lifetime_check CHECK (not_before < not_after)
);
CREATE INDEX mls_member_packages_device_id_idx ON mls_member_packages USING btree (device_id);
--> statement-breakpoint
-- Every package id ever published, kept after the package is replaced,
-- consumed or its channel deleted: a package id is published only once.
CREATE TABLE mls_published_package_ids (
  package_id uuid PRIMARY KEY,
  channel_id uuid NOT NULL,
  device_id uuid NOT NULL REFERENCES devices(id),
  published_at timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE mls_group_members (
  channel_id uuid NOT NULL REFERENCES channels(id),
  genesis_version integer NOT NULL,
  device_id uuid NOT NULL,
  user_id uuid NOT NULL,
  leaf_index integer NOT NULL,
  joined_version integer NOT NULL,
  removed_version integer,
  -- A package is used once; a device that rejoins publishes a new one.
  package_id uuid NOT NULL,
  key_package text NOT NULL,
  package_signature text NOT NULL,
  -- The user's directory head when the device was added, so a device that
  -- joins later verifies the roster as it was at that version.
  joined_directory_sequence integer NOT NULL,
  -- The leaf signature key never changes; the HPKE key follows UpdatePaths.
  signature_key text NOT NULL,
  encryption_key text NOT NULL,
  leaf_updated_at timestamp with time zone DEFAULT now() NOT NULL,
  last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
  PRIMARY KEY (channel_id, device_id, joined_version),
  CONSTRAINT mls_group_members_package_id_unique UNIQUE (package_id),
  CONSTRAINT mls_group_members_device_user_fk FOREIGN KEY (device_id, user_id) REFERENCES devices(id, user_id),
  CONSTRAINT mls_group_members_leaf_index_check CHECK (leaf_index >= 0),
  CONSTRAINT mls_group_members_joined_version_check CHECK (joined_version >= genesis_version),
  CONSTRAINT mls_group_members_removed_version_check CHECK (removed_version IS NULL OR removed_version > joined_version),
  CONSTRAINT mls_group_members_directory_sequence_check CHECK (joined_directory_sequence BETWEEN 0 AND 8192)
);
CREATE UNIQUE INDEX mls_group_members_current_device_idx ON mls_group_members USING btree (channel_id, device_id) WHERE removed_version IS NULL;
CREATE UNIQUE INDEX mls_group_members_current_leaf_idx ON mls_group_members USING btree (channel_id, leaf_index) WHERE removed_version IS NULL;
CREATE INDEX mls_group_members_device_id_idx ON mls_group_members USING btree (device_id);
CREATE INDEX mls_group_members_channel_user_idx ON mls_group_members USING btree (channel_id, user_id);
CREATE INDEX mls_group_members_user_channel_idx ON mls_group_members USING btree (user_id, channel_id);
--> statement-breakpoint
-- HPKE keys of every UpdatePath node (leaf and parents) a group has
-- accepted. Parent keys stay in the ratchet tree without a member row; a new
-- leaf or node reusing one would make every later commit fail. Append-only.
CREATE TABLE mls_group_node_keys (
  channel_id uuid NOT NULL REFERENCES channels(id),
  genesis_version integer NOT NULL,
  key text NOT NULL,
  PRIMARY KEY (channel_id, genesis_version, key)
);
--> statement-breakpoint
CREATE TABLE mls_rejoin_requests (
  channel_id uuid NOT NULL REFERENCES channels(id),
  device_id uuid NOT NULL REFERENCES devices(id),
  requested_at timestamp with time zone DEFAULT now() NOT NULL,
  -- The active version when the device asked to be added again.
  version integer NOT NULL,
  PRIMARY KEY (channel_id, device_id, requested_at)
);
--> statement-breakpoint
-- Pending epochs never authorized ciphertext. Abort them with the same
-- cleanup as abortPendingChannelKeyEpochs: clear acknowledgements, then the
-- deliveries, then the recipient snapshot.
UPDATE channel_key_epoch_recipients AS recipient
SET accepted_delivery_id = NULL, acknowledgement_signature = NULL, acknowledged_at = NULL
FROM channel_key_epochs AS epoch
WHERE epoch.channel_id = recipient.channel_id
  AND epoch.version = recipient.version
  AND epoch.status = 'pending';
DELETE FROM channel_keys AS delivery
USING channel_key_epochs AS epoch
WHERE epoch.channel_id = delivery.channel_id
  AND epoch.version = delivery.version
  AND epoch.status = 'pending';
DELETE FROM channel_key_epoch_recipients AS recipient
USING channel_key_epochs AS epoch
WHERE epoch.channel_id = recipient.channel_id
  AND epoch.version = recipient.version
  AND epoch.status = 'pending';
UPDATE channel_key_epochs SET status = 'aborted', aborted_at = now() WHERE status = 'pending';
--> statement-breakpoint
-- Earlier epochs stay readable. New writes need a v4 group first.
UPDATE channels SET key_rotation_required = true WHERE id IN (
  SELECT channel_id FROM channel_key_epochs WHERE status = 'active'
);
