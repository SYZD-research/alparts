#!/bin/sh
# Install the Quint and TLC tools the *Q models use (see quint/README.md).
#   formal-model/.tools/node_modules/.bin/quint   quint (npm)
#   ~/.quint/apalache-dist-0.62.4/apalache         Apalache, which also contains TLC
# Java 17 or later must be on PATH.
set -eu
cd "$(dirname "$0")/.."
npm install --no-save --prefix .tools @informalsystems/quint@0.33.1
dist="$HOME/.quint/apalache-dist-0.62.4"
if [ ! -f "$dist/apalache/lib/apalache.jar" ]; then
  mkdir -p "$dist"
  curl -fsSL https://github.com/apalache-mc/apalache/releases/download/v0.62.4/apalache.tgz | tar xz -C "$dist"
fi
java -version
.tools/node_modules/.bin/quint --version
