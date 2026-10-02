#!/usr/bin/env bash
# Start a disposable S3-compatible object store (SeaweedFS) for CI and wait
# until its bucket exists.
#
# Usage: start-object-storage.sh <container> <host-port> <bucket>
# Credentials come from OBJECT_STORAGE_ACCESS_KEY / OBJECT_STORAGE_SECRET_KEY.
set -euo pipefail

container=$1
port=$2
bucket=$3
: "${OBJECT_STORAGE_ACCESS_KEY:?}"
: "${OBJECT_STORAGE_SECRET_KEY:?}"

# SeaweedFS 4.47 (Apache-2.0).
image='chrislusf/seaweedfs:4.47@sha256:ce9e796f1fe6f06968f4c04bdaf8f678dad9c8acdfef3d244133d71bfa6bf882'

config=$(mktemp)
chmod 644 "$config"
printf '{"identities":[{"name":"admin","credentials":[{"accessKey":"%s","secretKey":"%s"}],"actions":["Admin","Read","List","Tagging","Write"]}]}\n' \
  "$OBJECT_STORAGE_ACCESS_KEY" "$OBJECT_STORAGE_SECRET_KEY" > "$config"

docker run --detach --name "$container" --publish "127.0.0.1:${port}:8333" \
  --volume "${config}:/etc/seaweedfs/s3.json:ro,z" \
  "$image" mini -dir=/data -s3.config=/etc/seaweedfs/s3.json -bucket="$bucket" \
  -master.telemetry=false -admin.ui=false -webdav=false -s3.port.iceberg=0 -s3.port.lance=0 >/dev/null

for _ in $(seq 1 90); do
  if echo s3.bucket.list | docker exec -i "$container" weed shell 2>/dev/null \
    | grep -qE "^[[:space:]]+${bucket}[[:space:]]"; then
    exit 0
  fi
  sleep 1
done
echo "Object storage did not become ready" >&2
docker logs "$container" >&2 || true
exit 1
