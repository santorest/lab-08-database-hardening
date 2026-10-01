-- Disable and rename the built-in sa login (MS-01). It is found by its fixed SID, so the script is re-runnable.
-- Last script on purpose: the first pass runs as sa, and every connection it needs (master, clinic) is already open,
-- so disabling sa does not cut the run short. Later passes log in as lab_admin.
DECLARE @name sysname = (SELECT name FROM sys.server_principals WHERE sid = 0x01);
IF @name <> N'lab_sa_disabled'
BEGIN
    DECLARE @sql nvarchar(400) = N'ALTER LOGIN ' + QUOTENAME(@name) + N' WITH NAME = [lab_sa_disabled];';
    EXEC sys.sp_executesql @sql;
END
GO
ALTER LOGIN [lab_sa_disabled] DISABLE;
GO
