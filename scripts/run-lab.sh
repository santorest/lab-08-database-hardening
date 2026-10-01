#!/usr/bin/env bash
# The whole lab for one engine: default container -> seed -> before -> harden (2 passes around a restart) -> after
# -> harden again (idempotence) -> after-again -> report -> gate. Same script in CI and locally.
# Needs Docker, `pip install -r requirements.txt && pip install --no-deps -e .`, the secrets from ci-secrets.sh in
# the environment, certs/ from make-certs.sh, and for SQL Server the ODBC Driver 18 and certs/ca.crt in the system
# trust store.
set -euo pipefail
engine="${1:?usage: run-lab.sh mssql|postgres}"
out="out/$engine"
mkdir -p "$out"

case "$engine" in
  mssql)
    export MSSQL_HOST=localhost MSSQL_PORT=1433 MSSQL_USER=sa MSSQL_PASSWORD="$SA_PASSWORD" MSSQL_TRUST_SERVER_CERT=yes
    docker rm -f lab-mssql >/dev/null 2>&1 || true
    docker run -d --name lab-mssql -e ACCEPT_EULA=Y -e MSSQL_PID=Developer -e MSSQL_SA_PASSWORD="$SA_PASSWORD" \
      -p 1433:1433 "${MSSQL_IMAGE:?set MSSQL_IMAGE}" >/dev/null
    dbhardening wait --engine mssql --timeout 180
    dbhardening run-sql --engine mssql --dir seed/mssql
    dbhardening collect --engine mssql --out "$out/before.json"
    scripts/configure-mssql.sh
    dbhardening harden --engine mssql                       # pass 1, as sa
    docker restart lab-mssql >/dev/null
    export MSSQL_USER=lab_admin MSSQL_PASSWORD="$ADMIN_PASSWORD" MSSQL_TRUST_SERVER_CERT=no
    dbhardening wait --engine mssql --timeout 180
    dbhardening harden --engine mssql                       # pass 2, as lab_admin, certificate verified
    ;;
  postgres)
    export PGHOST=localhost PGPORT=5432 PGUSER=postgres PGPASSWORD="$PG_ADMIN_PASSWORD" PGDATABASE=clinic PGSSLMODE=prefer
    docker rm -f lab-postgres >/dev/null 2>&1 || true
    docker build -q -t lab-postgres:local docker/postgres >/dev/null
    docker run -d --name lab-postgres -e POSTGRES_PASSWORD="$PG_ADMIN_PASSWORD" -e POSTGRES_DB=clinic \
      -p 5432:5432 lab-postgres:local >/dev/null
    dbhardening wait --engine postgres --timeout 120
    dbhardening run-sql --engine postgres --dir seed/postgres
    dbhardening collect --engine postgres --out "$out/before.json"
    scripts/configure-postgres.sh
    dbhardening harden --engine postgres                    # pass 1
    docker restart lab-postgres >/dev/null
    export PGSSLMODE=verify-full PGSSLROOTCERT="$PWD/certs/ca.crt"
    dbhardening wait --engine postgres --timeout 120
    dbhardening harden --engine postgres                    # pass 2 (creates the pgaudit extension)
    ;;
  *) echo "unknown engine: $engine" >&2; exit 2 ;;
esac

dbhardening collect --engine "$engine" --out "$out/after.json"
dbhardening harden --engine "$engine"                       # pass 3: must change nothing
dbhardening collect --engine "$engine" --out "$out/after-again.json"
dbhardening report --before "$out/before.json" --after "$out/after.json" \
  --html "$out/report.html" --markdown "$out/report.md"
dbhardening assess "$out/before.json" --json "$out/findings-before.json" > "$out/assess-before.txt"
dbhardening assess "$out/after.json" --json "$out/findings-after.json" --fail-on High | tee "$out/assess-after.txt"
