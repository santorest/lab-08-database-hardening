# Shipping the audit trail to Wazuh

> **Not run in this lab.** CI proves the events are recorded (see the integration tests and `audit-proof.json` in the
> run artifacts). This page sketches how they would reach the Wazuh SIEM from Lab 01; the decoders and rules are not
> written or tested here.

## SQL Server

SQL Server Audit writes binary `.sqlaudit` files that Wazuh cannot read directly. Export them on a schedule with
`sys.fn_get_audit_file` to JSON lines, keeping the last `event_time` read so each run only exports new rows:

```sql
SELECT event_time, action_id, succeeded, server_principal_name, database_name, object_name, statement
FROM sys.fn_get_audit_file(N'/var/opt/mssql/audit/*.sqlaudit', DEFAULT, DEFAULT)
WHERE event_time > @last_exported
FOR JSON PATH;
```

Wazuh agent (`ossec.conf`):

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/mssql-audit/audit.jsonl</location>
</localfile>
```

## PostgreSQL

Use `log_destination = 'jsonlog'` (or keep `csvlog` with a CSV decoder) and point the agent at the log directory:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/lib/postgresql/18/docker/log/*.json</location>
</localfile>
```

## Events and the detections they would feed

| Event proven in CI | SQL Server | PostgreSQL | Detection idea | ATT&CK |
|---|---|---|---|---|
| Failed login | `action_id = LGIF` | core log `FATAL 28P01 password authentication failed` | several failures for one login or from one client in a short window | T1110 (Brute Force) |
| Role membership change | `action_id = APRL` (add member) | pgAudit `SESSION … ROLE, GRANT ROLE` | any change to an administrative role outside a change window | T1098 (Account Manipulation) |
| Read of a sensitive table | `action_id = SL` on `dbo.patients` | pgAudit `OBJECT … READ, SELECT, TABLE, public.patients` | unusual volume or an unexpected principal reading patient data | T1005 (Data from Local System) |
