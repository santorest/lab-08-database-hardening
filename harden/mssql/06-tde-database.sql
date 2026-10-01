-- database: clinic
IF NOT EXISTS (SELECT 1 FROM sys.dm_database_encryption_keys WHERE database_id = DB_ID())
    CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256 ENCRYPTION BY SERVER CERTIFICATE lab_tde_cert;
GO
IF NOT EXISTS (SELECT 1 FROM sys.databases WHERE database_id = DB_ID() AND is_encrypted = 1)
    ALTER DATABASE clinic SET ENCRYPTION ON;
GO
-- Encryption runs in the background; wait (up to 2 minutes) so the assessment that follows sees the end state.
DECLARE @waited int = 0;
WHILE @waited < 120 AND EXISTS (SELECT 1 FROM sys.dm_database_encryption_keys
                                WHERE database_id = DB_ID() AND encryption_state <> 3)
BEGIN
    WAITFOR DELAY '00:00:01';
    SET @waited += 1;
END
GO
