-- Server audit to files + the key server events (MS-07).
IF NOT EXISTS (SELECT 1 FROM sys.server_audits WHERE name = N'lab_audit')
    CREATE SERVER AUDIT lab_audit
        TO FILE (FILEPATH = N'/var/opt/mssql/audit/', MAXSIZE = 64 MB, MAX_ROLLOVER_FILES = 10)
        WITH (ON_FAILURE = CONTINUE);
GO
IF NOT EXISTS (SELECT 1 FROM sys.dm_server_audit_status WHERE name = N'lab_audit' AND status_desc = N'STARTED')
    ALTER SERVER AUDIT lab_audit WITH (STATE = ON);
GO
IF NOT EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = N'lab_server_spec')
    CREATE SERVER AUDIT SPECIFICATION lab_server_spec FOR SERVER AUDIT lab_audit
        ADD (FAILED_LOGIN_GROUP),
        ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP),
        ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP),
        ADD (SERVER_PERMISSION_CHANGE_GROUP),
        ADD (DATABASE_PERMISSION_CHANGE_GROUP)
        WITH (STATE = ON);
GO
