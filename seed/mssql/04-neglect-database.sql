-- database: clinic
-- Seeded: the app user is db_owner (MS-10) and guest can connect (MS-09).
IF USER_ID(N'clinic_app') IS NULL CREATE USER clinic_app FOR LOGIN clinic_app;
GO
IF IS_ROLEMEMBER(N'db_owner', N'clinic_app') = 0 ALTER ROLE db_owner ADD MEMBER clinic_app;
GRANT CONNECT TO guest;
GO
