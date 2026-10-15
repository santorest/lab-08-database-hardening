# PostgreSQL 18.6 with pgAudit from the PostgreSQL Global Development Group repository (already configured in the image).
FROM postgres:18.6-trixie@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-18-pgaudit=18.0-3.pgdg13+1 \
 && rm -rf /var/lib/apt/lists/*
