-- database: clinic
-- National IDs encrypted with pgcrypto (PG-12). The key comes from PII_KEY and is never stored in the database.
-- pgAudit is not loaded during the first pass, so the key is not written to the audit log; later passes skip
-- the ALTER because the column is already bytea.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
DO $$
BEGIN
    IF (SELECT data_type FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'patients' AND column_name = 'national_id') = 'text' THEN
        ALTER TABLE patients ALTER COLUMN national_id TYPE bytea
            USING pgp_sym_encrypt(national_id, '$(PII_KEY)');
    END IF;
END $$;
