-- Surface area (MS-03, MS-04, MS-12). 'remote access' takes effect after the restart that follows this pass.
-- An option is changed only when its value differs from the target: SQL Server on Linux rejects sp_configure for
-- features it does not support (xp_cmdshell, for one), and those already sit at the safe value.
EXEC sp_configure N'show advanced options', 1;
RECONFIGURE;
GO
DECLARE @targets TABLE (name nvarchar(70) PRIMARY KEY, target int NOT NULL);
INSERT @targets (name, target) VALUES
    (N'xp_cmdshell', 0), (N'Ole Automation Procedures', 0), (N'Ad Hoc Distributed Queries', 0),
    (N'remote access', 0), (N'clr strict security', 1), (N'cross db ownership chaining', 0);
DECLARE @name nvarchar(70), @target int;
DECLARE options CURSOR LOCAL FAST_FORWARD FOR
    SELECT t.name, t.target FROM @targets AS t
    JOIN sys.configurations AS c ON c.name = t.name
    WHERE CAST(c.value AS int) <> t.target;
OPEN options;
FETCH NEXT FROM options INTO @name, @target;
WHILE @@FETCH_STATUS = 0
BEGIN
    EXEC sp_configure @name, @target;
    FETCH NEXT FROM options INTO @name, @target;
END
CLOSE options;
DEALLOCATE options;
RECONFIGURE;
GO
EXEC sp_configure N'show advanced options', 0;
RECONFIGURE;
GO
