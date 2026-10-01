-- database: clinic
-- Every SELECT on the patients table is audited (MS-07).
IF NOT EXISTS (SELECT 1 FROM sys.database_audit_specifications WHERE name = N'lab_clinic_spec')
    CREATE DATABASE AUDIT SPECIFICATION lab_clinic_spec FOR SERVER AUDIT lab_audit
        ADD (SELECT ON OBJECT::dbo.patients BY public)
        WITH (STATE = ON);
GO
