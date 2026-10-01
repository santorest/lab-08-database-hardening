-- Common neglected-server states, seeded on purpose so the "before" assessment reflects a typical server.
-- Seeded here: clinic_app without password policy (MS-02), cross-database ownership chaining on (MS-12),
-- TRUSTWORTHY on (MS-11). xp_cmdshell (MS-03) is not seeded: SQL Server on Linux does not support it.
-- Everything else in "before" comes from the container defaults.
IF SUSER_ID(N'clinic_app') IS NULL
    CREATE LOGIN clinic_app WITH PASSWORD = N'$(APP_PASSWORD)', CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF;
GO
EXEC sp_configure N'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure N'cross db ownership chaining', 1;
RECONFIGURE;
GO
ALTER DATABASE clinic SET TRUSTWORTHY ON;
GO
