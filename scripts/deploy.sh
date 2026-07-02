#!/usr/bin/env bash
# bullnym deploy: git pull → build → install. Run as debian on the prod VM.
#   ./deploy.sh           full deploy (pull, cargo build, binary + PWA + migrations check, restart)
#   ./deploy.sh --pwa     PWA-only (pull, copy dist; no build, no restart — shells are read per-request)
set -euo pipefail

REPO=$HOME/src/bullnym
APP=/opt/payservice
source "$HOME/.cargo/env"

cd "$REPO"
git fetch origin
git reset --hard origin/main
echo "deploying $(git log --oneline -1)"

deploy_pwa() {
  sudo rm -rf "$APP/pwa/dist.new"
  sudo cp -r "$REPO/pwa/dist" "$APP/pwa/dist.new"
  sudo chown -R payservice:payservice "$APP/pwa/dist.new"
  sudo rm -rf "$APP/pwa/dist.prev"
  if [ -d "$APP/pwa/dist" ]; then sudo mv "$APP/pwa/dist" "$APP/pwa/dist.prev"; fi
  sudo mv "$APP/pwa/dist.new" "$APP/pwa/dist"
  echo "PWA dist deployed"
}

if [ "${1:-}" = "--pwa" ]; then
  deploy_pwa
  exit 0
fi

echo "NOTE: migrations are applied manually and deliberately:"
echo "  PGPASSWORD=\$(cat ~/.pgpass_payservice) psql -h 127.0.0.1 -U payservice -d payservice -f migrations/NNN_*.sql"
ls -1 "$REPO"/migrations | tail -3 | sed 's/^/  latest in repo: /'

export CARGO_BUILD_JOBS=2
cargo build --release

sudo install -o payservice -g payservice -m 755 "$REPO/target/release/pay-service" "$APP/pay-service.new"
sudo mv "$APP/pay-service.new" "$APP/pay-service"
deploy_pwa
sudo systemctl restart payservice
sleep 3
sudo systemctl is-active payservice
curl -s http://127.0.0.1:8080/ready && echo " ready"
