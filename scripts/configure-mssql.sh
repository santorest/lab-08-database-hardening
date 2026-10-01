#!/usr/bin/env bash
# Container-level SQL Server hardening: TLS certificate, mssql.conf, audit and backup folders. Read at next restart.
set -euo pipefail
c=lab-mssql
docker exec -u root "$c" mkdir -p /var/opt/mssql/certs /var/opt/mssql/audit /var/opt/mssql/backup
docker cp certs/server.crt "$c":/var/opt/mssql/certs/server.crt
docker cp certs/server.key "$c":/var/opt/mssql/certs/server.key
docker cp harden/mssql/mssql.conf "$c":/var/opt/mssql/mssql.conf
docker exec -u root "$c" chown -R mssql /var/opt/mssql/certs /var/opt/mssql/audit /var/opt/mssql/backup \
  /var/opt/mssql/mssql.conf
docker exec -u root "$c" chmod 600 /var/opt/mssql/certs/server.key
