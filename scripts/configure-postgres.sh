#!/usr/bin/env bash
# Container-level PostgreSQL hardening: certificate, conf.d/hardening.conf, pg_hba.conf. Read at next restart.
set -euo pipefail
c=lab-postgres
data="$(docker exec "$c" sh -c 'printf %s "$PGDATA"')"   # PostgreSQL 18 images use /var/lib/postgresql/18/docker
docker exec "$c" mkdir -p "$data/conf.d" "$data/certs"
docker cp certs/server.crt "$c":"$data/certs/server.crt"
docker cp certs/server.key "$c":"$data/certs/server.key"
docker cp harden/postgres/conf.d/hardening.conf "$c":"$data/conf.d/hardening.conf"
docker cp harden/postgres/pg_hba.conf "$c":"$data/pg_hba.conf"
docker exec "$c" chown -R postgres:postgres "$data/conf.d" "$data/certs" "$data/pg_hba.conf"
docker exec "$c" chmod 600 "$data/certs/server.key"
line="include_dir = 'conf.d'"
docker exec "$c" sh -c "grep -qxF \"$line\" \"$data/postgresql.conf\" || echo \"$line\" >> \"$data/postgresql.conf\""
