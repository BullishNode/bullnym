#!/usr/bin/env bash
# Exercise the passive manifest store against a disposable real S3-compatible
# endpoint. Images are pinned by digest; override them only for deliberate
# compatibility testing.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MINIO_IMAGE="${MINIO_IMAGE:-quay.io/minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e}"
MINIO_MC_IMAGE="${MINIO_MC_IMAGE:-quay.io/minio/mc@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727}"
RUN_ID="${USER:-user}-$$-${RANDOM}"
CONTAINER="bullnym-minio-${RUN_ID}"
NETWORK="bullnym-minio-${RUN_ID}"
MINIO_USER="bullnymminiointegration"
MINIO_PASSWORD="bullnymminiointegrationsecret"
BUCKET="bullnym-manifest-integration"
CONTAINER_STARTED=0
NETWORK_STARTED=0
MODE="store"
DATA_VOLUME=""
CLEANUP_FAILURE_STATUS=87

die() {
  echo "test-swap-manifest-store-minio: $*" >&2
  exit 1
}

if (($# > 0)); then
  case "$1" in
    --delivery-coordinator)
      MODE="delivery-coordinator"
      shift
      ;;
    --cleanup-failure-probe)
      MODE="cleanup-failure-probe"
      shift
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
fi
(($# == 0)) || die "unexpected arguments"

command -v docker >/dev/null || die "docker is required"
command -v curl >/dev/null || die "curl is required"
docker info >/dev/null 2>&1 || die "docker daemon is unavailable"

cleanup() {
  local status=$?
  local cleanup_failed=0
  trap - EXIT

  if ((CONTAINER_STARTED == 1)); then
    if ((status != 0)) && [[ "$MODE" != "cleanup-failure-probe" ]]; then
      echo "test-swap-manifest-store-minio: MinIO log tail after failure:" >&2
      docker logs --tail 80 "$CONTAINER" >&2 || true
    fi
    docker rm --force --volumes "$CONTAINER" >/dev/null 2>&1 || cleanup_failed=1
  fi
  if ((NETWORK_STARTED == 1)); then
    docker network rm "$NETWORK" >/dev/null 2>&1 || cleanup_failed=1
  fi

  if docker inspect "$CONTAINER" >/dev/null 2>&1; then
    echo "test-swap-manifest-store-minio: container cleanup verification failed" >&2
    cleanup_failed=1
  fi
  if docker network inspect "$NETWORK" >/dev/null 2>&1; then
    echo "test-swap-manifest-store-minio: network cleanup verification failed" >&2
    cleanup_failed=1
  fi
  if [[ -n "$DATA_VOLUME" ]] && docker volume inspect "$DATA_VOLUME" >/dev/null 2>&1; then
    echo "test-swap-manifest-store-minio: anonymous data-volume cleanup verification failed" >&2
    cleanup_failed=1
  fi

  if ((cleanup_failed == 0)); then
    echo "test-swap-manifest-store-minio: verified container, network, and anonymous data-volume cleanup"
  else
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT

docker network create "$NETWORK" >/dev/null
NETWORK_STARTED=1

docker run --detach \
  --name "$CONTAINER" \
  --network "$NETWORK" \
  --env "MINIO_ROOT_USER=$MINIO_USER" \
  --env "MINIO_ROOT_PASSWORD=$MINIO_PASSWORD" \
  --publish 127.0.0.1::9000 \
  "$MINIO_IMAGE" \
  server /data --address :9000 --console-address :9001 >/dev/null
CONTAINER_STARTED=1

DATA_VOLUME="$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' "$CONTAINER")"
[[ "$DATA_VOLUME" =~ ^[0-9a-f]{64}$ ]] \
  || die "could not resolve the anonymous MinIO data volume"
if [[ "$MODE" == "cleanup-failure-probe" ]]; then
  echo "test-swap-manifest-store-minio: exercising intentional post-start cleanup failure path"
  exit "$CLEANUP_FAILURE_STATUS"
fi

HOST_PORT="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "9000/tcp") 0).HostPort}}' "$CONTAINER")"
[[ "$HOST_PORT" =~ ^[0-9]+$ ]] || die "could not resolve the published MinIO port"
ENDPOINT="http://127.0.0.1:${HOST_PORT}"

READY=0
for _ in $(seq 1 60); do
  if curl --fail --silent --show-error "$ENDPOINT/minio/health/ready" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 0.5
done
((READY == 1)) || die "MinIO did not become ready within 30 seconds"

docker run --rm \
  --network "$NETWORK" \
  --env "MC_HOST_local=http://${MINIO_USER}:${MINIO_PASSWORD}@${CONTAINER}:9000" \
  "$MINIO_MC_IMAGE" \
  mb --ignore-existing "local/${BUCKET}" >/dev/null

if [[ "$MODE" == "delivery-coordinator" ]]; then
  DELIVERY_PREFIX="bullnym/delivery/${RUN_ID}"
  docker run --rm \
    --network "$NETWORK" \
    --env "MC_HOST_local=http://${MINIO_USER}:${MINIO_PASSWORD}@${CONTAINER}:9000" \
    "$MINIO_MC_IMAGE" \
    version enable "local/${BUCKET}" >/dev/null

  set +e
  scripts/test-db.sh --mode fresh --cleanup-failure-probe
  DB_CLEANUP_PROBE_STATUS=$?
  set -e
  [[ "$DB_CLEANUP_PROBE_STATUS" == "86" ]] \
    || die "PostgreSQL failure-path cleanup probe did not finish cleanly"

  echo "test-swap-manifest-store-minio: running ignored PostgreSQL + S3 delivery contract"
  BULLNYM_MINIO_ENDPOINT="$ENDPOINT" \
  BULLNYM_MINIO_BUCKET="$BUCKET" \
  BULLNYM_MINIO_ACCESS_KEY="$MINIO_USER" \
  BULLNYM_MINIO_SECRET_KEY="$MINIO_PASSWORD" \
  BULLNYM_MINIO_DELIVERY_PREFIX="$DELIVERY_PREFIX" \
    scripts/test-db.sh --mode fresh --ignored --locked \
    --filter manifest_delivery_coordinator_real_postgres_minio_contract

  VERSION_LIST="$(docker run --rm \
    --network "$NETWORK" \
    --env "MC_HOST_local=http://${MINIO_USER}:${MINIO_PASSWORD}@${CONTAINER}:9000" \
    "$MINIO_MC_IMAGE" \
    ls --versions --recursive --json "local/${BUCKET}/${DELIVERY_PREFIX}")"
  VERSION_COUNT="$(awk 'NF { count += 1 } END { print count + 0 }' <<<"$VERSION_LIST")"
  [[ "$VERSION_COUNT" == "3" ]] \
    || die "expected exactly three retained object versions, observed ${VERSION_COUNT}"
  echo "test-swap-manifest-store-minio: verified three objects with one retained version each"
else
  echo "test-swap-manifest-store-minio: running ignored S3 contract test"
  BULLNYM_MINIO_ENDPOINT="$ENDPOINT" \
  BULLNYM_MINIO_BUCKET="$BUCKET" \
  BULLNYM_MINIO_ACCESS_KEY="$MINIO_USER" \
  BULLNYM_MINIO_SECRET_KEY="$MINIO_PASSWORD" \
    cargo test --locked --test swap_manifest_store_minio \
    minio_exercises_manifest_store_contract_and_redaction -- \
    --ignored --exact
fi
