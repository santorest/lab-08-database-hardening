-- database: clinic
IF OBJECT_ID(N'dbo.patients') IS NULL
    CREATE TABLE dbo.patients (
        id int IDENTITY(1, 1) PRIMARY KEY,
        full_name nvarchar(100) NOT NULL,
        national_id nvarchar(20) NOT NULL);
IF OBJECT_ID(N'dbo.appointments') IS NULL
    CREATE TABLE dbo.appointments (
        id int IDENTITY(1, 1) PRIMARY KEY,
        patient_id int NOT NULL REFERENCES dbo.patients (id),
        starts_at datetime2(0) NOT NULL,
        reason nvarchar(200) NOT NULL);
GO
IF NOT EXISTS (SELECT 1 FROM dbo.patients)
BEGIN
    INSERT dbo.patients (full_name, national_id)
    VALUES (N'Ana Example', N'X-1001'), (N'Bruno Example', N'X-1002'), (N'Carla Example', N'X-1003');
    INSERT dbo.appointments (patient_id, starts_at, reason)
    VALUES (1, '2026-10-05T09:00:00', N'Check-up'), (2, '2026-10-05T10:00:00', N'Follow-up'),
           (3, '2026-10-06T11:00:00', N'Vaccination');
END
GO
