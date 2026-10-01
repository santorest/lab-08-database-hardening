# PostgreSQL 18.6 with pgAudit from the PostgreSQL Global Development Group repository (already configured in the image).
FROM postgres:18.6-trixie@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-18-pgaudit=18.0-3.pgdg13+1 \
 && rm -rf /var/lib/apt/lists/*
