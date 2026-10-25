#!/usr/bin/env bash
# Installs the pinned dirdoc into /usr/local/bin for the maintenance jobs. The
# Go checksum database verifies what is downloaded. Run it before any code
# from the change can run: the command sandbox mounts /usr/local/bin
# read-only, so nothing the model writes can replace it.
set -euo pipefail

module=github.com/SYZD-research/dirdoc/cmd/dirdoc
version=v0.1.1-0.20261025165917-3edf8cd8d820

gobin=$(mktemp -d)
GOBIN="$gobin" go install "$module@$version"
sudo install -m 0755 "$gobin/dirdoc" /usr/local/bin/dirdoc
rm -rf "$gobin"
dirdoc --version
