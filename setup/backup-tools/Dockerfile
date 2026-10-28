# The tools scripts/backup.sh and scripts/prune-backups.sh need, for the
# backups the setup runs in a container: the PostgreSQL 16 client from the same
# image as the database (pg_dump must match the server's major version), GNU
# userland, and rclone and age, whose Alpine packages are older than the
# versions backup.sh requires (rclone 1.75.1 or later, and age 1.3.0 or later
# for its hybrid recipients). The official release files of rclone 1.75.2 and
# age 1.3.2 are pinned by checksum.
FROM postgres:16.15-alpine3.23@sha256:731499cca67dd6cbb34bbffbf489bda72aa31252b14bcc0eafdccbb92c4b2446

ARG TARGETARCH
# These Alpine packages are not pinned: a build takes the current fixes of the
# 3.23 branch, whose old versions the repository does not keep. The image tag
# names this file, not the package versions, so builds of one tag on two hosts
# can differ in them; the base image, rclone and age cannot.
RUN apk add --no-cache bash coreutils diffutils findutils gawk grep jq sed tar unzip

RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) rclone_sha256=349ac8fba6ff65d6247043f1750cdcb518ec5d500ef91463a10d37c0ccdf3702; \
             age_sha256=cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10 ;; \
      arm64) rclone_sha256=7e1e8d69654941b7b7df84ee74c5f7fb09cce7d5496947fb7bf16b55ff427d10; \
             age_sha256=6b8dc4333c53a5a57c9e5834e3a48f92605d7154014cd07269ff3327db5d37f4 ;; \
      *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    arch="${TARGETARCH:-amd64}"; \
    work="$(mktemp -d)"; \
    wget -q -O "$work/rclone.zip" "https://downloads.rclone.org/v1.75.2/rclone-v1.75.2-linux-${arch}.zip"; \
    echo "${rclone_sha256}  $work/rclone.zip" | sha256sum -c -; \
    unzip -q -j "$work/rclone.zip" "rclone-v1.75.2-linux-${arch}/rclone" -d /usr/local/bin; \
    wget -q -O "$work/age.tar.gz" "https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-${arch}.tar.gz"; \
    echo "${age_sha256}  $work/age.tar.gz" | sha256sum -c -; \
    tar -xzf "$work/age.tar.gz" -C /usr/local/bin --strip-components=1 age/age age/age-keygen; \
    chmod 0755 /usr/local/bin/rclone /usr/local/bin/age /usr/local/bin/age-keygen; \
    rm -rf "$work"; \
    rclone version | head -n 1; \
    age --version

# The image's unprivileged postgres user (uid 70, BACKUP_USER in
# setup/src/files.ts) owns the backup credentials and directories.
USER postgres
ENTRYPOINT []
