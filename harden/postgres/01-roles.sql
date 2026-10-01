-- database: clinic
-- App role without extra attributes and with a SCRAM password (PG-02, PG-04); owner and auditor roles.
SET password_encryption = 'scram-sha-256';
ALTER ROLE clinic_app NOSUPERUSER NOCREATEROLE NOCREATEDB PASSWORD '$(APP_PASSWORD)';
RESET password_encryption;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'clinic_owner') THEN
        CREATE ROLE clinic_owner NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auditor') THEN
        CREATE ROLE auditor NOLOGIN;
    END IF;
END $$;
