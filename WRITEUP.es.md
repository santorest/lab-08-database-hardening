---
title: "Endurecimiento y auditoría de SQL Server y PostgreSQL"
id: "lab-08-database-hardening"
category: "Seguridad de bases de datos"
type: "Laboratorio"
status: "completado"
date: "2026-10-01"
time_to_reproduce: "15–20 minutos (fork, activar Actions, ejecutar CI); más o menos lo mismo en local con Docker"
skills: [SQL Server, PostgreSQL, pgAudit, pgcrypto, T-SQL, Python, pytest, Docker, OpenSSL, GitHub Actions]
frameworks: [CIS Controls v8 (3.10, 3.11, 4.1, 5.4, 6.8, 8.2, 16.12), MITRE ATT&CK (T1190, T1110, T1078, T1098)]
repo: "https://github.com/santorest/lab-08-database-hardening"
bundle: "Publicado en el sitio del portafolio con su checksum SHA-256"
---

# Endurecimiento y auditoría de SQL Server y PostgreSQL

> **Resumen:** un SQL Server 2025 y un PostgreSQL 18 con la configuración por defecto se evalúan con 12 controles
> cada uno, se endurecen con scripts idempotentes (TLS, TDE o pgcrypto, mínimo privilegio, una auditoría que
> funciona), se vuelven a evaluar con el mismo código y se atacan con una pequeña demostración de inyección SQL antes
> y después de la corrección. Todo se ejecuta en GitHub Actions contra contenedores. **Las ejecuciones de CI son
> reales; los datos son sintéticos.** Nunca se ha ejecutado en un servidor de producción.

| | |
|---|---|
| **Rol** | Ingeniero de bases de datos / seguridad que lleva dos servidores descuidados a una línea base defendible |
| **Entorno** | Repositorio público de GitHub, runners Ubuntu de GitHub, contenedores de SQL Server 2025 Developer y PostgreSQL 18.6 |
| **Herramientas** | Python 3.12, pyodbc + ODBC Driver 18, psycopg 3, pgAudit, pgcrypto, OpenSSL, pytest, ruff, mypy, gitleaks |
| **Entregable** | Herramienta de evaluación (24 controles), scripts de carga y de endurecimiento, prueba de auditoría, demostración de inyección SQL, CI, ruleset de rama, PR de demostración |

---

## 1. Problema

Los servidores de bases de datos se instalan a menudo con la configuración por defecto y nunca se revisan: el
administrador integrado sigue activo, las conexiones no van cifradas, nada se audita y la aplicación se conecta con una
cuenta que es dueña de todo. Las guías de endurecimiento enumeran las correcciones, pero suelen quedar dos preguntas:
*¿la corrección cambió de verdad el servidor?* y *¿rompió la aplicación?* Este laboratorio responde ambas con
evidencia: los mismos controles se ejecutan antes y después, y las consultas de la propia aplicación se ejecutan
contra el servidor endurecido.

## 2. Diseño

- **Recolectar → instantánea → controles.** Un recolector ejecuta consultas de solo lectura (solo `SELECT`/`SHOW`;
  una prueba unitaria falla si una consulta contiene otra cosa) y guarda una instantánea JSON de conjuntos de datos
  con nombre, cada uno con su estado. Los controles son funciones puras sobre esa instantánea, así que se prueban sin
  base de datos y funcionan sin conexión sobre la instantánea de cualquier servidor.
- **Nada pasa en silencio.** Si un conjunto de datos no se pudo recolectar, cada control que lo necesita informa
  *No evaluado*. Si el servidor no informa un parámetro, el control dice que no puede confirmar que sea seguro. La
  puerta de CI falla con un hallazgo alto **o** con un control alto que no se pudo evaluar.
- **Misma forma para ambos motores.** Un catálogo, un informe, una puerta; los nombres de SQL Server se comparan sin
  distinguir mayúsculas y los roles de PostgreSQL distinguiéndolas, como hace cada servidor.
- **Un "antes" honesto.** Los contenedores por defecto ya pasan algunos controles, así que un script de carga recrea
  algunos estados descuidados habituales (un login de la aplicación que es `db_owner` o dueño de sus tablas,
  `TRUSTWORTHY` activo, una columna de documento de identidad en texto plano…). Los resultados indican qué hallazgos
  del "antes" vienen de la configuración por defecto y cuáles de la carga.

## 3. Controles

| Id | SQL Server | Sev | | Id | PostgreSQL | Sev |
|---|---|---|---|---|---|---|
| MS-01 | `sa` activo o sin renombrar | Alta | | PG-01 | `trust`/`password`/`md5` en `pg_hba` | Alta |
| MS-02 | Logins SQL sin política de contraseñas | Media | | PG-02 | Hash de contraseñas MD5 | Media |
| MS-03 | `xp_cmdshell` activo | Alta | | PG-03 | TLS apagado o no obligatorio | Alta |
| MS-04 | Opciones de superficie riesgosas | Media | | PG-04 | Superusuarios inesperados / rol de aplicación privilegiado | Alta |
| MS-05 | Cifrado no forzado | Alta | | PG-05 | `pg_hba` abierto a cualquier dirección | Media |
| MS-06 | Sin TDE | Media | | PG-06 | pgAudit sin configurar | Alta |
| MS-07 | La auditoría no cubre eventos clave | Alta | | PG-07 | Registro de conexiones incompleto | Media |
| MS-08 | Sysadmins inesperados | Alta | | PG-08 | `PUBLIC` puede crear en `public` | Media |
| MS-09 | `guest` puede conectarse | Media | | PG-09 | Rol de aplicación con privilegios de más | Media |
| MS-10 | Login de aplicación con privilegios de más | Media | | PG-10 | `SECURITY DEFINER` sin `search_path` | Alta |
| MS-11 | `TRUSTWORTHY` activo | Alta | | PG-11 | Lenguaje no confiable marcado como confiable | Alta |
| MS-12 | Encadenamiento de propiedad entre bases de datos | Baja | | PG-12 | Columna sensible en texto plano | Media |

Cada control, su consulta y su paso de endurecimiento se describen en `docs/checks.md`.

## 4. Endurecimiento

- **SQL Server:** un `lab_admin` con nombre reemplaza a `sa`, que se renombra y desactiva al final (la ejecución
  conserva las conexiones que abrió como `sa`); se quitan de `sysadmin` los principales de Windows que la imagen de
  Linux trae en ese rol; se apagan las opciones riesgosas (solo cuando difieren, porque SQL Server en Linux rechaza las
  opciones que no admite); un certificado del laboratorio y `forceencryption`; TDE con un certificado cuya copia, en un
  servidor real, debe guardarse fuera de línea; una auditoría de servidor para inicios de sesión fallidos y cambios de
  roles y permisos, y una auditoría de base de datos de cada SELECT sobre `patients`; el login de la aplicación pierde
  `db_owner` y recibe un rol con exactamente las sentencias que necesita.
- **PostgreSQL:** `pg_hba.conf` solo con `scram-sha-256` y `hostssl` para el rango de la red puente de Docker; TLS
  activo; el rol de la aplicación pierde CREATEDB, su contraseña se vuelve a calcular con SCRAM y sus tablas pasan a
  un rol propietario sin login; `PUBLIC` pierde CREATE en `public`; la función `SECURITY DEFINER` recibe un
  `search_path` fijo; el documento de identidad pasa a ser un `bytea` cifrado con pgcrypto con la clave tomada del
  entorno; pgAudit registra las clases `role` y `ddl`, y cada lectura de `patients` mediante auditoría de objetos.
- **Dos pasadas y una tercera.** Algunos parámetros necesitan reinicio, y la extensión pgAudit solo se puede crear
  cuando la biblioteca ya está precargada, así que el endurecimiento se ejecuta antes y después del reinicio. Una
  tercera ejecución no debe cambiar la instantánea; CI las compara.

## 5. Prueba de auditoría e inyección SQL

Tras el endurecimiento, las pruebas de integración **provocan** los eventos y luego los **encuentran**: un inicio de
sesión fallido, un cambio de pertenencia a un rol y una lectura de la tabla de pacientes, en `sys.fn_get_audit_file`
en SQL Server y en el registro de PostgreSQL (el registro del servidor para el inicio de sesión fallido, pgAudit para
los otros dos).

La aplicación de demostración tiene una sola búsqueda, `find_appointments(patient_name)`, escrita dos veces. La
versión vulnerable pega el nombre en el texto SQL; la corregida lo pasa como parámetro. Ambas se ejecutan con el login
de la aplicación con mínimo privilegio. El mínimo privilegio no detiene la inyección —la búsqueda vulnerable sigue
filtrando el nombre de todos los pacientes—, pero sí detiene el daño: un `DROP TABLE` apilado se rechaza porque el
login de la aplicación ya no es dueño de la tabla. La versión parametrizada trata cada carga maliciosa como dato.

## 6. Resultados

Todas las cifras provienen de ejecuciones de GitHub Actions del 2026-10-01. La referencia es la primera ejecución
completamente verde en `main`,
[run 36903937272](https://github.com/santorest/lab-08-database-hardening/actions/runs/36903937272): pasaron los 5
jobs, 107 pruebas unitarias con 96,75 % de cobertura, y cada job de base de datos pasó sus 8 pruebas de integración.
Los informes completos de esa ejecución están en `docs/example-report-mssql.html` y `docs/example-report-postgres.html`.

**Antes y después del endurecimiento** (mismos controles, mismo código):

| Motor | Antes: alta / media / baja | Después: alta / media / baja | No evaluados (después) |
|---|---|---|---|
| SQL Server 17.0.5005.3 (2025), Enterprise Developer | 7 / 6 / 1 | 0 / 0 / 0 | 0 |
| PostgreSQL 18.6 con pgAudit | 11 / 11 / 0 | 0 / 0 / 0 | 0 |

**De dónde salieron los hallazgos del "antes":**

| Motor | De la configuración por defecto del contenedor | De la carga |
|---|---|---|
| SQL Server | 9: `sa` activo y llamado `sa` (MS-01 ×2), `sa` sin caducidad (MS-02), `remote access` activo (MS-04), cifrado no forzado (MS-05), sin TDE (MS-06), sin auditoría (MS-07), `BUILTIN\Administrators` y `NT AUTHORITY\NETWORK SERVICE` en `sysadmin` (MS-08 ×2) | 5: login de la aplicación sin política de contraseñas (MS-02), acceso de `guest` (MS-09), login de la aplicación `db_owner` (MS-10), `TRUSTWORTHY` (MS-11), encadenamiento entre bases de datos (MS-12) |
| PostgreSQL | 13: seis reglas `trust` (PG-01 ×6), SSL apagado y una regla remota sin TLS (PG-03 ×2), una regla abierta a cualquier dirección (PG-05), sin pgAudit (PG-06), registro de conexiones apagado y un prefijo de registro incompleto (PG-07 ×3) | 9: contraseña de la aplicación guardada como MD5 (PG-02), rol de la aplicación con CREATEDB (PG-04), CREATE de `PUBLIC` en `public` (PG-08), rol de la aplicación dueño de dos tablas y de sus dos secuencias de identidad (PG-09 ×4), `SECURITY DEFINER` sin `search_path` (PG-10), documento de identidad en texto plano (PG-12) |

MS-03 y PG-11 pasaron antes y después: SQL Server en Linux no admite `xp_cmdshell`, y el contenedor de PostgreSQL no
tiene lenguajes no confiables instalados.

**Idempotencia:** en ambos motores, la instantánea tomada tras una tercera ejecución del endurecimiento fue idéntica a
la del "después" (sin contar marcas de tiempo ni la lista de sesiones activas).

**Prueba de auditoría** (eventos provocados por las pruebas y luego encontrados):

| Evento | SQL Server (`sys.fn_get_audit_file`) | PostgreSQL |
|---|---|---|
| Inicio de sesión fallido | `LGIF` de `clinic_app`: "Password did not match that for the login provided" | `FATAL 28P01 password authentication failed for user "clinic_app"` (registro del servidor) |
| Cambio de pertenencia a un rol | `APRL` por `lab_admin`: `ALTER SERVER ROLE securityadmin ADD MEMBER [audit_probe_…]` | pgAudit `AUDIT: SESSION … ROLE, GRANT ROLE` |
| Lectura de pacientes | `SL` sobre `patients` por `clinic_app` | pgAudit `AUDIT: OBJECT … READ, SELECT, TABLE, public.patients` |

**Inyección SQL**, en ambos motores y con el login de la aplicación con mínimo privilegio: la búsqueda vulnerable
devolvió 1 fila para "Ana Example", las 3 citas con `x' OR '1'='1` y los tres nombres de pacientes mediante una carga
`UNION`; la búsqueda corregida devolvió la única fila correcta y nada para cada carga maliciosa. Un
`DROP TABLE appointments` apilado a través de la búsqueda vulnerable fue rechazado (PostgreSQL: "must be owner") y la
tabla siguió existiendo. El login de la aplicación no pudo hacer `DELETE` sobre `patients`.

**Ruleset** `24324399` en `main`: pull request obligatorio, los 5 controles obligatorios y actualizados, historial
lineal, sin force push ni borrado.

**Dos pull requests de demostración, ambos bloqueados** (cerrados sin fusionar):

| PR | Cambio | Qué falló | Fusión |
|---|---|---|---|
| [#1](https://github.com/santorest/lab-08-database-hardening/pull/1) | Quitar `forceencryption = 1` de la configuración de SQL Server | `mssql` en la puerta: MS-05 alta siguió después del endurecimiento ([run](https://github.com/santorest/lab-08-database-hardening/actions/runs/36905489784)) | Bloqueada |
| [#2](https://github.com/santorest/lab-08-database-hardening/pull/2) | Las búsquedas "corregidas" vuelven a construir el SQL con la entrada | `unit` (la carga ya no viaja como parámetro) y los dos jobs de base de datos (las cargas devuelven filas) ([run](https://github.com/santorest/lab-08-database-hardening/actions/runs/36905503447)) | Bloqueada |

En el PR #2 el linter siguió en verde: la regla de inyección SQL de ruff no ve `.format()` sobre una constante, así
que solo las pruebas se interpusieron entre el cambio y `main`.

## 7. Lecciones

- **SQL Server en Linux no es SQL Server en Windows.** La primera ejecución falló porque Linux rechaza
  `sp_configure 'xp_cmdshell'`. El script de endurecimiento ahora cambia una opción solo cuando difiere del objetivo,
  y MS-03 simplemente pasa en Linux.
- **La configuración por defecto esconde sorpresas que vale la pena encontrar.** La primera ejecución completa mostró
  dos principales de Windows en `sysadmin` en un servidor Linux. La evaluación los detectó después del endurecimiento,
  y ahora se quitan en lugar de añadirse a una lista de permitidos.
- **Los formatos de registro muerden en lo pequeño.** El registro CSV de PostgreSQL duplica las comillas alrededor del
  nombre de usuario, así que la prueba no encontraba el inicio de sesión fallido hasta buscar la forma escapada; el
  endurecimiento estaba bien, la prueba no.
- **Las pruebas pueden fallar por el motivo equivocado.** Un parámetro llamado `settings` en una función auxiliar de
  las pruebas se tragaba el conjunto de datos de PostgreSQL con el mismo nombre, y diez pruebas fallaban aunque el
  código era correcto. La función ahora lo recibe por posición.

## 8. Límites

- Contenedores y datos sintéticos; nunca se ha ejecutado en un servidor de producción.
- Se nombran las áreas de los benchmarks de CIS; no se citan números de recomendación.
- El cifrado en reposo de PostgreSQL es una columna con pgcrypto; el cifrado del volumen es el control real y no se
  prueba. PG-12 comprueba el tipo de la columna, no que los bytes estén cifrados.
- MS-03 (sin `xp_cmdshell` en Linux) y PG-11 (sin lenguajes no confiables instalados) pasan antes y después; solo
  tienen pruebas unitarias.
- Los controles de ámbito de base de datos miran la base de datos de la aplicación; MS-10 y PG-09 no son un motor
  completo de permisos efectivos.
- El envío de la auditoría a Wazuh está documentado (`docs/wazuh-shipping.md`) pero no se ejecuta.

## 9. Cómo reproducirlo

Haz un fork del repositorio y activa Actions: cada push ejecuta el laboratorio completo. En local (Linux, macOS o WSL
con Docker), sigue el inicio rápido del README: `scripts/run-lab.sh postgres` y `scripts/run-lab.sh mssql` escriben
las instantáneas y los informes en `out/`.

## 10. Correspondencia con marcos

| Marco | Elementos |
|---|---|
| CIS Controls v8 | 3.10 cifrar datos en tránsito, 3.11 cifrar datos en reposo, 4.1 proceso de configuración segura, 5.4 restringir privilegios de administrador, 6.8 control de acceso basado en roles, 8.2 recolectar registros de auditoría, 16.12 controles de seguridad a nivel de código |
| MITRE ATT&CK | T1190 Exploit Public-Facing Application (inyección SQL), T1110 Brute Force (inicios de sesión fallidos auditados), T1078 Valid Accounts (administrador por defecto), T1098 Account Manipulation (cambios de roles auditados) |
