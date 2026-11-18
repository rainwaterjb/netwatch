#!/bin/sh
# Update NetWatch, or switch to a specific release (roll back or forward).
#
#   ./update.sh            update to the latest release (recommended)
#   ./update.sh v1.2.0     switch to release v1.2.0 (roll back or forward)
#   ./update.sh --list     list releases, show which one is running and if an update is out
#   ./update.sh main       run the newest unreleased code (for testing)
#
# Your .env and data volume are never touched (.env is not tracked by Git).
set -eu

# Run from a temporary copy, so checking out another version can't change
# this script while it's running.
if [ -z "${NETWATCH_UPDATE_DIR:-}" ]; then
  NETWATCH_UPDATE_DIR=$(cd "$(dirname "$0")" && pwd)
  export NETWATCH_UPDATE_DIR
  tmp=$(mktemp)
  cp "$0" "$tmp"
  trap 'rm -f "$tmp"' EXIT
  sh "$tmp" "$@"
  exit $?
fi
cd "$NETWATCH_UPDATE_DIR"

current() { git describe --tags --always 2>/dev/null; }
latest() { git tag -l 'v[0-9]*' --sort=-v:refname | head -n 1; }

echo "==> Fetching releases"
git fetch --quiet --tags --prune --prune-tags origin

case "${1:-}" in
  -l|--list)
    echo "Available releases (newest first):"
    git tag -l 'v*' --sort=-v:refname --format='  %(refname:short)  %(creatordate:short)  %(contents:subject)'
    echo "Currently running: $(current)"
    if [ -n "$(latest)" ] && [ "$(current)" != "$(latest)" ]; then
      echo "Latest release:    $(latest)   (update with: ./update.sh)"
    fi
    exit 0 ;;
  -h|--help)
    sed -n '2,9p' "$0"; exit 0 ;;
esac

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "Local changes to tracked files found; refusing to switch versions:" >&2
  git status --short --untracked-files=no >&2
  echo "Undo them with: git checkout -- .   (your .env is not affected)" >&2
  exit 1
fi

before=$(current)
target=${1:-$(latest)}
if [ "$target" = "main" ] || [ -z "$target" ]; then
  echo "==> Updating to the newest code on main (unreleased)"
  git checkout --quiet main
  git pull --quiet --ff-only origin main
else
  set -- "$target"
  if ! git rev-parse --quiet --verify "refs/tags/$1^{commit}" >/dev/null; then
    echo "Unknown release '$1'. Run ./update.sh --list to see releases." >&2
    exit 1
  fi
  if [ "$1" = "$(latest)" ]; then echo "==> Updating to the latest release, $1"; else echo "==> Switching to release $1"; fi
  git -c advice.detachedHead=false checkout --quiet "$1"
fi
version=$(current)

echo "==> Building $version (pulling base-image security updates)"
docker compose build --pull --build-arg NETWATCH_VERSION="$version"

echo "==> Restarting"
docker compose up -d

docker compose ps
echo "==> Done: $before -> $version"
if [ "$target" != "main" ] && [ -n "$(latest)" ] && [ "$version" != "$(latest)" ]; then
  # Releases before v1.3.1 ship an older update.sh that can't switch versions,
  # so check out main first; that works from every version.
  echo "    Latest release is $(latest). To go back to it later: git checkout main && ./update.sh"
fi
