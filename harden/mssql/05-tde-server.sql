-- TDE keys in master (MS-06). The certificate backup stays in the container volume in this lab; on a real server
-- copy it offline, or the database cannot be restored anywhere else.
IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = N'##MS_DatabaseMasterKey##')
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = N'$(TDE_MASTER_KEY_PASSWORD)';
GO
IF NOT EXISTS (SELECT 1 FROM sys.certificates WHERE name = N'lab_tde_cert')
BEGIN
    CREATE CERTIFICATE lab_tde_cert WITH SUBJECT = N'Lab 08 TDE certificate';
    BACKUP CERTIFICATE lab_tde_cert TO FILE = N'/var/opt/mssql/backup/lab_tde_cert.cer'
        WITH PRIVATE KEY (FILE = N'/var/opt/mssql/backup/lab_tde_cert.pvk',
                          ENCRYPTION BY PASSWORD = N'$(TDE_BACKUP_PASSWORD)');
END
GO
