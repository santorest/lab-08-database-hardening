# Checks

Every check is a pure function over a snapshot (`src/dbhardening/checks/mssql.py`, `checks/pg.py`). It reads one or
more **datasets**, each collected by one read-only query (the `Q_*` constants in `collect_mssql.py` /
`collect_pg.py`). If any dataset a check needs is missing or failed to collect, the check reports one
**Not evaluated** finding with the reason; it never returns a silent pass. A setting the server did not report at all
produces a "cannot confirm" finding for the same reason.

Settings (allowed administrators, app login/role, app tables, audited tables, sensitive columns, required pgAudit
classes) live in `src/dbhardening/defaults.toml` and can be overridden with `--settings FILE`. SQL Server names are
compared case-insensitively; PostgreSQL role names case-sensitively, as each server does.

"Before in the lab" says where the lab's starting state comes from: the container **default**, or the **seed**
scripts (`seed/`), which recreate common neglected-server states on purpose.

## SQL Server

| Id | Flags | Dataset (query) | Hardened by | CIS area | Before in the lab |
|---|---|---|---|---|---|
| MS-01 | The login with SID `0x01` (`sa`) is enabled, or still named `sa` | `logins` (`Q_LOGINS`) | `harden/mssql/09-sa.sql`: rename to `lab_sa_disabled`, disable; `01-admin.sql` creates `lab_admin` first | Authentication | default |
| MS-02 | Enabled SQL logins with `CHECK_POLICY` off; enabled **sysadmin** SQL logins with `CHECK_EXPIRATION` off | `logins`, `sysadmins` | `03-logins.sql`; `lab_admin` is created with both on | Authentication | default (`sa`) and seed (`clinic_app`) |
| MS-03 | `xp_cmdshell` = 1 | `configurations` (`Q_CONFIGURATIONS`) | `02-surface.sql` | Surface area reduction | passes: SQL Server on Linux does not support `xp_cmdshell` |
| MS-04 | `clr enabled` without `clr strict security`; `Ole Automation Procedures`, `Ad Hoc Distributed Queries`, `remote access` on | `configurations` | `02-surface.sql` (changes an option only when it differs from the target, because Linux rejects unsupported options) | Surface area reduction | default (`remote access`) |
| MS-05 | A probe connection made with `Encrypt=no` arrives unencrypted (so the server does not force encryption); the detail counts unencrypted sessions | `connection_probe` (`Q_PROBE`), `sessions` (`Q_SESSIONS`) | `scripts/configure-mssql.sh` + `harden/mssql/mssql.conf` (`forceencryption = 1`, lab certificate), restart | Encryption in transit | default |
| MS-06 | A user database whose `encryption_state` is not 3 | `databases` (`Q_DATABASES`) | `05-tde-server.sql` (master key, certificate, backup), `06-tde-database.sql` (DEK, `SET ENCRYPTION ON`, waits for state 3) | Encryption at rest | default |
| MS-07 | No started server audit; a server audit specification missing `FAILED_LOGIN_GROUP`, `SERVER_ROLE_MEMBER_CHANGE_GROUP`, `DATABASE_ROLE_MEMBER_CHANGE_GROUP`, `SERVER_PERMISSION_CHANGE_GROUP` or `DATABASE_PERMISSION_CHANGE_GROUP`; an `audited_tables` entry without a SELECT audit | `server_audits`, `server_audit_actions`, `db_audit_actions` | `07-audit-server.sql`, `08-audit-database.sql` (file target `/var/opt/mssql/audit/`) | Auditing and logging | default |
| MS-08 | `sysadmin` members other than `sa` and `allowed_sysadmins` | `sysadmins` (`Q_SYSADMINS`) | `01-admin.sql` removes `BUILTIN\Administrators` and `NT AUTHORITY\NETWORK SERVICE`, which the Linux image makes sysadmin | Authorization | default |
| MS-09 | `guest` holds CONNECT in a user database | `guest` (`Q_GUEST`, every user database) | `04-app-database.sql` | Authorization | seed |
| MS-10 | App user in a fixed database role; grants outside the app tables; anything WITH GRANT OPTION | `app_roles`, `app_grants` (app database) | `04-app-database.sql`: `clinic_app_role` with SELECT on patients, SELECT/INSERT/UPDATE on appointments | Authorization | seed (`db_owner`) |
| MS-11 | `TRUSTWORTHY` on | `databases` | `03-logins.sql` | Authorization | seed |
| MS-12 | `cross db ownership chaining` on for the instance or a database | `configurations`, `databases` | `02-surface.sql` | Authorization | seed |

## PostgreSQL

| Id | Flags | Dataset (query) | Hardened by | CIS area | Before in the lab |
|---|---|---|---|---|---|
| PG-01 | `pg_hba` rules using `trust`, `password` or `md5`; rules that failed to parse | `hba` (`Q_HBA`) | `harden/postgres/pg_hba.conf`: `local` and `hostssl 172.16.0.0/12`, both `scram-sha-256` | Authentication | default (six `trust` rules) |
| PG-02 | `password_encryption` other than `scram-sha-256`; roles whose stored password is an MD5 hash | `settings`, `password_hashes` (hash kind only) | `conf.d/hardening.conf`, `01-roles.sql` resets the app password as SCRAM | Authentication | seed (`clinic_app` MD5) |
| PG-03 | `ssl` off; `host`/`hostnossl` rules for non-loopback addresses | `settings`, `hba` | lab certificate, `ssl = on`, `hostssl` only | Encryption in transit | default |
| PG-04 | Superusers outside `allowed_superusers`; app role with CREATEROLE or CREATEDB, or a member (directly or through other roles) of a superuser role | `roles`, `app_memberships` | `01-roles.sql` | Authorization | seed (CREATEDB) |
| PG-05 | Non-local rules open to every address (`all`, `0.0.0.0/0`, `::/0`) | `hba` | `pg_hba.conf` (Docker bridge range only) | Network access | default |
| PG-06 | pgAudit not preloaded, or `pgaudit.log` missing a required class (`role`, `ddl`), including one subtracted from `all` (`all, -role`) | `settings` | `docker/postgres/Dockerfile` (pgAudit package), `hardening.conf`, `04-pgaudit.sql` (extension, after the restart) | Auditing and logging | default |
| PG-07 | `log_connections` empty/off (PostgreSQL 18 takes a list), `log_disconnections` off, `log_line_prefix` without user, database and client | `settings` | `hardening.conf` | Auditing and logging | default |
| PG-08 | `PUBLIC` has CREATE on schema `public` | `public_schema` (every database) | `02-privileges.sql` | Authorization | seed |
| PG-09 | Objects owned by the app role or a role it belongs to (tables, their identity sequences, functions); privileges, its own or inherited, outside SELECT/INSERT/UPDATE/DELETE on the app tables; schema privileges other than USAGE; membership in a broad predefined role (`pg_read_all_data`, `pg_write_all_data`, the server-file and server-program roles) | `app_owned`, `app_grants`, `app_memberships` | `02-privileges.sql`: owner `clinic_owner` (NOLOGIN), narrow grants | Authorization | seed |
| PG-10 | `SECURITY DEFINER` functions without `search_path` in `proconfig` | `secdef_functions` | `02-privileges.sql` (`SET search_path = public, pg_temp`) | Code and extensions | seed |
| PG-11 | An untrusted language (`plpython3u`, `plperlu`, `pltclu`…) marked `lanpltrusted` | `languages` | — | Code and extensions | passes: no untrusted language is installed |
| PG-12 | A `sensitive_columns` entry not stored as `bytea`, or not found | `sensitive_columns` | `03-pgcrypto.sql` (`pgp_sym_encrypt` with a key from the environment) | Encryption at rest | seed |

PG-12 checks the column **type**: `bytea` is what pgcrypto produces, but the check cannot prove the bytes are
encrypted. Encryption of the data files themselves (volume encryption) is the real at-rest control and is not tested
here.
