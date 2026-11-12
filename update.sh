#!/bin/sh
# Pull the latest NetWatch code and rebuild/restart the container.
# Your .env and data volume are untouched (.env is not tracked by Git).
set -eu
cd "$(dirname "$0")"

echo "==> Fetching latest code"
git pull --ff-only

echo "==> Rebuilding image (pulling base-image security updates)"
docker compose build --pull

echo "==> Restarting"
docker compose up -d

docker compose ps
echo "==> Done. Logs: docker compose logs -f"
