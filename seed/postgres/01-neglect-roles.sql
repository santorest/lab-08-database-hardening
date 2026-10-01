-- database: clinic
-- Seeded: the app role can create databases (PG-04) and its password is stored as an MD5 hash (PG-02).
-- The clinic database itself is created by the container (POSTGRES_DB=clinic).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'clinic_app') THEN
        CREATE ROLE clinic_app LOGIN CREATEDB;
    END IF;
END $$;
SET password_encryption = 'md5';
ALTER ROLE clinic_app PASSWORD '$(APP_PASSWORD)';
RESET password_encryption;
