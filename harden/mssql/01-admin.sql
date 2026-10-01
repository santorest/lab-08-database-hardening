-- A named administrator replaces sa (MS-01, MS-08). Password policy and expiry on, as MS-02 expects for sysadmins.
IF SUSER_ID(N'lab_admin') IS NULL
    CREATE LOGIN lab_admin WITH PASSWORD = N'$(ADMIN_PASSWORD)', CHECK_POLICY = ON, CHECK_EXPIRATION = ON;
GO
IF IS_SRVROLEMEMBER(N'sysadmin', N'lab_admin') = 0 ALTER SERVER ROLE sysadmin ADD MEMBER lab_admin;
GO
-- The Linux image makes two Windows principals sysadmin; nothing in this lab authenticates as them (MS-08).
IF EXISTS (SELECT 1 FROM sys.server_role_members AS rm
           JOIN sys.server_principals AS m ON m.principal_id = rm.member_principal_id
           WHERE rm.role_principal_id = SUSER_ID(N'sysadmin') AND m.name = N'BUILTIN\Administrators')
    ALTER SERVER ROLE sysadmin DROP MEMBER [BUILTIN\Administrators];
IF EXISTS (SELECT 1 FROM sys.server_role_members AS rm
           JOIN sys.server_principals AS m ON m.principal_id = rm.member_principal_id
           WHERE rm.role_principal_id = SUSER_ID(N'sysadmin') AND m.name = N'NT AUTHORITY\NETWORK SERVICE')
    ALTER SERVER ROLE sysadmin DROP MEMBER [NT AUTHORITY\NETWORK SERVICE];
GO
