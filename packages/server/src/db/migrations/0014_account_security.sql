ALTER TABLE devices ADD COLUMN approved_at timestamptz;
UPDATE devices SET approved_at = created_at;
ALTER TABLE sessions ADD COLUMN authentication_method text NOT NULL DEFAULT 'password';
CREATE TABLE passkeys (
  id text PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id), name text NOT NULL,
  public_key text NOT NULL, counter bigint NOT NULL CHECK (counter >= 0), transports jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX passkeys_user_idx ON passkeys(user_id);
CREATE TABLE authentication_challenges (
  id uuid PRIMARY KEY, user_id uuid REFERENCES users(id), session_id uuid REFERENCES sessions(id) ON DELETE CASCADE,
  purpose text NOT NULL, challenge text NOT NULL, expires_at timestamptz NOT NULL
);
CREATE INDEX authentication_challenges_expiry_idx ON authentication_challenges(expires_at);
CREATE TABLE step_up_grants (
  token_hash text PRIMARY KEY, session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  purpose text NOT NULL, expires_at timestamptz NOT NULL
);
CREATE INDEX step_up_grants_session_idx ON step_up_grants(session_id);
CREATE TABLE device_directory_events (
  user_id uuid NOT NULL REFERENCES users(id), sequence integer NOT NULL CHECK (sequence BETWEEN 1 AND 8192),
  previous_hash text NOT NULL, hash text NOT NULL, event jsonb NOT NULL,
  PRIMARY KEY (user_id, sequence)
);
CREATE TABLE history_recovery (
  user_id uuid PRIMARY KEY REFERENCES users(id), generation uuid NOT NULL, signing_key text NOT NULL,
  encrypted_secret text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE history_recovery_keys (
  user_id uuid NOT NULL REFERENCES users(id), generation uuid NOT NULL,
  channel_id uuid NOT NULL REFERENCES channels(id), version integer NOT NULL CHECK (version >= 1),
  key_commitment text NOT NULL, ciphertext text NOT NULL,
  PRIMARY KEY (user_id, generation, channel_id, version)
);
--> statement-breakpoint
-- The pre-upgrade directory is explicitly a TOFU migration anchor, not an
-- assertion that these devices had owner approval before this release.
DO $$
DECLARE d record; u uuid; n integer := 0; prev text; h text; e jsonb; payload text;
BEGIN
  FOR d IN SELECT * FROM devices ORDER BY user_id, created_at, id LOOP
    IF u IS DISTINCT FROM d.user_id THEN u := d.user_id; n := 0; prev := repeat('0',64); END IF;
    n := n + 1;
    e := jsonb_build_object('kind','legacy','deviceId',d.id::text,'identityKey',d.identity_key,
      'actorDeviceId',d.id::text,'signature','','challenge',CASE WHEN d.revoked_at IS NULL THEN 'active' ELSE 'revoked' END);
    payload := '["alparts-directory",1,' || to_json(d.user_id::text)::text || ',' || n::text || ',' || to_json(prev)::text
      || ',"legacy",' || to_json(d.id::text)::text || ',' || to_json(d.identity_key)::text || ',' || to_json(d.id::text)::text
      || ',"",' || to_json(e->>'challenge')::text || ',null]';
    h := encode(sha256(convert_to(payload,'UTF8')),'hex');
    INSERT INTO device_directory_events VALUES (u,n,prev,h,e);
    prev := h;
  END LOOP;
END $$;
--> statement-breakpoint
CREATE FUNCTION reject_directory_rewrite() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'device directory is append-only'; END $$;
CREATE TRIGGER device_directory_no_rewrite BEFORE UPDATE OR DELETE ON device_directory_events
FOR EACH ROW EXECUTE FUNCTION reject_directory_rewrite();

--> statement-breakpoint
CREATE TABLE mls_key_packages (
  channel_id uuid NOT NULL REFERENCES channels(id), version integer NOT NULL,
  device_id uuid NOT NULL REFERENCES devices(id), package_id uuid NOT NULL UNIQUE,
  key_package text NOT NULL, signature text NOT NULL,
  PRIMARY KEY (channel_id, version, device_id)
);
CREATE TABLE mls_epochs (
  channel_id uuid NOT NULL REFERENCES channels(id), version integer NOT NULL,
  transcript text NOT NULL, envelope jsonb NOT NULL,
  PRIMARY KEY (channel_id, version)
);
-- Old epochs remain readable. New writes require migration to the group protocol.
UPDATE channels SET key_rotation_required = true WHERE EXISTS (
  SELECT 1 FROM channel_key_epochs e WHERE e.channel_id = channels.id AND e.status = 'active'
);

UPDATE channel_key_epochs SET status = 'aborted', aborted_at = now() WHERE status = 'pending';
