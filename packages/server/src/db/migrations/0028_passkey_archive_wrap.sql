-- A passkey now wraps only the key of the history archive, not the recovery
-- code. A wrap made before this sealed the code itself, so whoever could use
-- the passkey could also open the recovery signing key and approve a new
-- device. Those wraps are removed: the plans keep working with the code, and
-- an approved device can wrap the history key again with a passkey.
UPDATE "history_recovery"
SET "encrypted_secret" = jsonb_build_object('version', 2, 'codeSecret', "encrypted_secret"::jsonb -> 'codeSecret')::text
WHERE "encrypted_secret" LIKE '{%' AND ("encrypted_secret"::jsonb -> 'passkeyWrap' ->> 'version') = '1';
