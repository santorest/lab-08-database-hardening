-- Surface area (MS-03, MS-04, MS-12). 'remote access' takes effect after the restart that follows this pass.
EXEC sp_configure N'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure N'xp_cmdshell', 0;
EXEC sp_configure N'Ole Automation Procedures', 0;
EXEC sp_configure N'Ad Hoc Distributed Queries', 0;
EXEC sp_configure N'remote access', 0;
EXEC sp_configure N'clr strict security', 1;
EXEC sp_configure N'cross db ownership chaining', 0;
RECONFIGURE;
EXEC sp_configure N'show advanced options', 0;
RECONFIGURE;
GO
