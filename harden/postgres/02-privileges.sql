-- database: clinic
-- Objects owned by a NOLOGIN role, the app gets only what it needs (PG-09); no CREATE for PUBLIC (PG-08);
-- fixed search_path for the SECURITY DEFINER function (PG-10); object audit of patients through 'auditor' (PG-06).
ALTER TABLE patients OWNER TO clinic_owner;
ALTER TABLE appointments OWNER TO clinic_owner;
ALTER FUNCTION patient_count() OWNER TO clinic_owner;
REVOKE ALL ON patients, appointments FROM clinic_app;
GRANT SELECT ON patients TO clinic_app;
GRANT SELECT, INSERT, UPDATE ON appointments TO clinic_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER FUNCTION patient_count() SET search_path = public, pg_temp;
GRANT SELECT ON patients TO auditor;
