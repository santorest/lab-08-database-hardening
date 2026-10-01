-- A named administrator replaces sa (MS-01, MS-08). Password policy and expiry on, as MS-02 expects for sysadmins.
IF SUSER_ID(N'lab_admin') IS NULL
    CREATE LOGIN lab_admin WITH PASSWORD = N'$(ADMIN_PASSWORD)', CHECK_POLICY = ON, CHECK_EXPIRATION = ON;
GO
IF IS_SRVROLEMEMBER(N'sysadmin', N'lab_admin') = 0 ALTER SERVER ROLE sysadmin ADD MEMBER lab_admin;
GO
