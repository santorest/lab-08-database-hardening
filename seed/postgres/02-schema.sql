-- database: clinic
-- Sample "clinic" schema: fictional people, synthetic data.
-- Seeded: the app role owns the tables (PG-09), PUBLIC may create in schema public (PG-08), a SECURITY DEFINER
-- function without a fixed search_path (PG-10), the national ID stored as plain text (PG-12).
CREATE TABLE IF NOT EXISTS patients (
    id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    full_name text NOT NULL,
    national_id text NOT NULL);
CREATE TABLE IF NOT EXISTS appointments (
    id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    patient_id int NOT NULL REFERENCES patients (id),
    starts_at timestamp NOT NULL,
    reason text NOT NULL);
ALTER TABLE patients OWNER TO clinic_app;
ALTER TABLE appointments OWNER TO clinic_app;
INSERT INTO patients (full_name, national_id)
SELECT v.full_name, v.national_id
FROM (VALUES ('Ana Example', 'X-1001'), ('Bruno Example', 'X-1002'), ('Carla Example', 'X-1003'))
     AS v (full_name, national_id)
WHERE NOT EXISTS (SELECT 1 FROM patients);
INSERT INTO appointments (patient_id, starts_at, reason)
SELECT v.patient_id, v.starts_at, v.reason
FROM (VALUES (1, timestamp '2026-10-05 09:00', 'Check-up'), (2, timestamp '2026-10-05 10:00', 'Follow-up'),
             (3, timestamp '2026-10-06 11:00', 'Vaccination')) AS v (patient_id, starts_at, reason)
WHERE NOT EXISTS (SELECT 1 FROM appointments);
GRANT CREATE ON SCHEMA public TO PUBLIC;
CREATE OR REPLACE FUNCTION patient_count() RETURNS bigint
    LANGUAGE sql SECURITY DEFINER
    AS $$ SELECT count(*) FROM patients $$;
