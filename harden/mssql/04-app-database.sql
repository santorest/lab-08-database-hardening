-- database: clinic
-- Least privilege for the app (MS-10) and no guest access (MS-09).
IF DATABASE_PRINCIPAL_ID(N'clinic_app_role') IS NULL CREATE ROLE clinic_app_role;
GO
GRANT SELECT ON dbo.patients TO clinic_app_role;
GRANT SELECT, INSERT, UPDATE ON dbo.appointments TO clinic_app_role;
IF IS_ROLEMEMBER(N'clinic_app_role', N'clinic_app') = 0 ALTER ROLE clinic_app_role ADD MEMBER clinic_app;
IF IS_ROLEMEMBER(N'db_owner', N'clinic_app') = 1 ALTER ROLE db_owner DROP MEMBER clinic_app;
REVOKE CONNECT FROM guest;
GO
