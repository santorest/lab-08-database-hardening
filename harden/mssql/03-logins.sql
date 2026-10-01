-- Password policy for the app login (MS-02) and TRUSTWORTHY off (MS-11).
ALTER LOGIN clinic_app WITH CHECK_POLICY = ON;
GO
ALTER DATABASE clinic SET TRUSTWORTHY OFF;
GO
