-- A passkey now wraps only the key of the history archive, not the recovery
-- code. A wrap made before this sealed the code itself, so whoever could use
-- the passkey could also open the recovery signing key and approve a new
-- device. Those wraps are removed: the plans keep working with the code, and
-- an approved device can wrap the history key again with a passkey.
--
-- Every secret that starts with "{" was written by configureRecovery, which
-- refuses anything but a JSON object with a string codeSecret. The preflight
-- stops before changing data if a row says otherwise, rather than casting a
-- broken row or writing a plan without its code secret. CASE keeps the cast
-- from reaching secrets of the older, base64 form.
DO $passkey_wrap_preflight$
BEGIN
  IF EXISTS (SELECT 1 FROM "history_recovery"
             WHERE "encrypted_secret" LIKE '{%' AND NOT ("encrypted_secret" IS JSON OBJECT)) THEN
    RAISE EXCEPTION 'passkey wrap preflight: a recovery secret is not a JSON object';
  END IF;
  IF EXISTS (SELECT 1 FROM "history_recovery"
             WHERE CASE WHEN "encrypted_secret" LIKE '{%'
                        THEN jsonb_typeof("encrypted_secret"::jsonb -> 'codeSecret') IS DISTINCT FROM 'string'
                        ELSE false END) THEN
    RAISE EXCEPTION 'passkey wrap preflight: a recovery secret has no code secret';
  END IF;
END $passkey_wrap_preflight$;--> statement-breakpoint
UPDATE "history_recovery"
SET "encrypted_secret" = jsonb_build_object('version', 2, 'codeSecret', "encrypted_secret"::jsonb -> 'codeSecret')::text
WHERE CASE WHEN "encrypted_secret" LIKE '{%'
           THEN ("encrypted_secret"::jsonb -> 'passkeyWrap' ->> 'version') = '1'
           ELSE false END;
