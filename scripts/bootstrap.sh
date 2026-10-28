#!/usr/bin/env bash
# One-time setup: pull the upstream juliogomez/pqc repo as a pinned submodule
# (we build its Dockerfiles unmodified) and generate lab secrets.
set -euo pipefail
cd "$(dirname "$0")/.."

UPSTREAM_DIR=vendor/juliogomez-pqc
UPSTREAM_URL=https://github.com/juliogomez/pqc.git

if [[ ! -d .git ]]; then
  echo ">> Initialising git repository"
  git init -q
fi

if [[ ! -f "$UPSTREAM_DIR/learn/docker/Dockerfile" ]]; then
  echo ">> Adding upstream labs as a submodule: $UPSTREAM_URL"
  # If .gitmodules already lists it (fresh clone), just init; otherwise add.
  if git config -f .gitmodules --get "submodule.$UPSTREAM_DIR.url" >/dev/null 2>&1 \
     && git ls-files --stage "$UPSTREAM_DIR" | grep -q '^160000'; then
    git submodule update --init --recursive "$UPSTREAM_DIR"
  else
    git submodule add -f "$UPSTREAM_URL" "$UPSTREAM_DIR"
  fi
fi

echo ">> Upstream at: $(git -C "$UPSTREAM_DIR" log -1 --format='%h %ad %s' --date=short)"
echo "   Pin it deliberately: cd $UPSTREAM_DIR && git checkout <sha> && cd - && git add $UPSTREAM_DIR"

if [[ ! -f .env ]]; then
  ./scripts/gen-lab-secrets.sh
else
  echo ">> .env exists - leaving secrets alone (run 'make secrets' to rotate)"
fi

echo ">> Next: make preflight && make up"
