Default mount/secret source for optional production settings in
`compose.production.yml`. `empty` is an intentionally empty file: an unset
optional secret (metrics token, previous password pepper) reads as "not
configured". Point the matching `*_SECRET_FILE` / `AUDIT_WITNESS_DIR` variable
at real files to enable a feature; never put secrets in this directory.
