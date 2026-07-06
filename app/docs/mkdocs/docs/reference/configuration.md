# Configuration reference

This document describes the different Signare command arguments and its static configuration file possible
attributes.

The target audience of this document is every user seeking precise configuration details.

## Static configuration

To configure Signare, you must use a YAML configuration file called `signare-config.yml`.
Here is a configuration example:

```yaml
logger:
  logLevel: 'info'
database:
  postgresql:
    host: 'localhost'
    port: 5432
    scheme: 'postgres'
    database: 'db_signare'
    username: 'signare'
    password: '__CHANGE_ME__'
    sslmode: 'require'
requestContext:
  userRequestHeader: 'X-Auth-UserId'
  applicationRequestHeader: 'X-Auth-ApplicationId'
metrics:
  prometheus:
    port: 9092
    path: /metrics
    maxRequestInFlight: 10
    timeoutInMillis: 30000
    namespace: 'signer'
hsmmodules:
  softhsm:
    lib: '/usr/local/lib/softhsm/libsofthsm2.so'
  akv:
    url: 'https://signare.vault.azure.net/'
server:
  maxRequestBodyBytes: 1048576
  maxHeaderBytes: 1048576
```

!!! warning

    The example above ships with safe-by-default values. Do not weaken them for production.

    - Connect with a **dedicated low-privilege role** (`signare` in the examples) that owns only the
      Signare database, not the `postgres` superuser. The bundled `create-databases.sql` creates such a
      role.
    - Keep `sslmode` at `require` or stronger. `disable` sends all database traffic, including the HSM
      slot credentials stored in the database, in clear text. See the SSL modes in the
      [database reference](./database.md){:target="_blank"}. Signare logs a startup warning when
      `sslmode` does not encrypt the connection (`disable`, `allow`, or `prefer`).
    - Do not commit the database password to the YAML file. Supply it through the
      `SIGNARE_DATABASE_POSTGRESQL_PASSWORD` environment variable (see below); the `__CHANGE_ME__`
      placeholder is intentionally invalid.
    - `info` is the recommended log level. `debug` can emit internal stack traces.

!!! info "Supplying configuration via the environment"

    The database password can be provided through the `SIGNARE_DATABASE_POSTGRESQL_PASSWORD`
    environment variable instead of the `database.postgresql.password` YAML field. When the environment
    variable is set it takes precedence over any value in the file, so the password never has to be
    written to disk in plaintext.

    More generally, any attribute present in the configuration file can be overridden by an environment
    variable named `SIGNARE_` followed by the uppercased attribute path with dots replaced by
    underscores, for example `SIGNARE_DATABASE_POSTGRESQL_HOST` or `SIGNARE_LOGGER_LOGLEVEL`. The
    password is the only key that can be supplied purely through the environment with no entry in the
    file.


Let us dive into the different attributes:

| Name               | Format                                                  | Required | Description                          |
|--------------------|---------------------------------------------------------|:--------:|--------------------------------------|
| **logger**         | [Logger configuration](#logger-configuration)           |    ✗     | Application logging configuration    |
| **database**       | [Database configuration](#database-configuration)       |    ✔     | General database configuration       |
| **requestContext** | [Request context](#request-context)                     |    ✗     | Authorization header key for Signare |
| **metrics**        | [Metrics configuration](#metrics-configuration)         |    ✗     | General metrics configuration        |
| **hsmmodules**     | [HSM Modules configuration](#hsm-modules-configuration) |    ✔     | HSM Modules types configuration      |
| **server**         | [Server configuration](#server-configuration)           |    ✗     | Request body and header size limits  |

### Logger configuration

| Name         | Type   | Required | Description                                            | Valid Values                 |
|--------------|--------|:--------:|--------------------------------------------------------|------------------------------|
| **logLevel** | string |    ✔     | Configuration of the  minimum level of logs to display | **INFO, WARN, ERROR, DEBUG** |

### Database configuration

| Name           | Type                                                    | Required | Description                                 |
|----------------|---------------------------------------------------------|:--------:|---------------------------------------------|
| **postgresql** | [PostgresSQL configuration](#postgressql-configuration) |    ✔     | Configuration of the postgres database type | 

!!! info
    The only supported databases are the ones that can be configured through this attribute.

### Request context

| Name                         | Type   | Required | Description                                                           | Default Value (if any) |
|------------------------------|--------|:--------:|-----------------------------------------------------------------------|------------------------|
| **userRequestHeader**        | string |    ✗     | Key's header to provide user to interact with Signare for RBAC        | X-Auth-UserId          |
| **applicationRequestHeader** | string |    ✗     | Key's header to provide application to interact with Signare for RBAC | X-Auth-ApplicationId   |

#### PostgresSQL configuration

| Name          | Type                                                                   | Required | Description                                                        |
|---------------|------------------------------------------------------------------------|:--------:|--------------------------------------------------------------------|
| **host**      | string                                                                 |    ✔     | Host url of the database                                           | 
| **port**      | int                                                                    |    ✔     | Port number of the database                                        | 
| **scheme**    | string                                                                 |    ✔     | Scheme of the database system                                      | 
| **username**  | string                                                                 |    ✔     | Username to use for the database connection                        | 
| **password**  | string                                                                 |    ✔     | Password to use along with the username in the database connection | 
| **sslmode**   | string                                                                 |    ✔     | SSLMode to use in the database system                              | 
| **database**  | string                                                                 |    ✔     | Database name                                                      | 
| **sqlClient** | [PostgresSQL client configuration](#postgres-sql-client-configuration) |    ✗     | Configuration of the database client                               | 

#### Postgres SQL client configuration

| Name                      | Type | Required | Description                                         | Default Value (if any) |
|---------------------------|------|:--------:|-----------------------------------------------------|------------------------|
| **maxIdleConnections**    | int  |    ✗     | Max idle connections for the database/sql handle    | 2                      |
| **maxOpenConnections**    | int  |    ✗     | Max open connections for the database/sql handle    | 100                    |
| **maxConnectionLifetime** | int  |    ✗     | Max connection lifetime for the database/sql handle | 0                      |

### Metrics configuration

| Name           | Type                                                          | Required | Description                            |
|----------------|---------------------------------------------------------------|:--------:|----------------------------------------|
| **prometheus** | [Prometheus configuration](#prometheus-metrics-configuration) |    ✔     | Configuration of the Prometheus system | 

!!! info
    The only supported monitoring systems are the ones that can be configured through this attribute.

#### Prometheus metrics configuration

| Name                    | Type   | Required | Description                                          | Default Value (if any) |
|-------------------------|--------|:--------:|------------------------------------------------------|------------------------|
| **port**                | int    |    ✗     | Port number where Prometheus metrics will be exposed | 9780                   |
| **path**                | string |    ✗     | URL path where prometheus will listen                | /metrics               |
| **maxRequestsInFlight** | int    |    ✗     | Number of concurrent HTTP requests                   | 10                     |
| **timeoutInMillis**     | int    |    ✗     | Number of millis until timeout                       | 30000                  |
| **namespace**           | string |    ✗     | Namespace to prefix metric names                     | signer                 |

### HSM Modules configuration

Signare provides support for different HSM types. Not all the supported HSMs require static configuration to function (check our [supported signing modules](./supported-modules.md)).

| Name        | Type                                            | Required | Description                      |
|-------------|-------------------------------------------------|:--------:|----------------------------------|
| **softhsm** | [SoftHSM configuration](#softhsm-configuration) |    ✗     | Configuration of the softhsm HSM | 
| **akv**     | [AKV configuration](#akv-configuration)         |    ✗     | Configuration of the akv hsm     |

#### SoftHSM Configuration

| Name        | Type   | Required | Description                              | Default Value (if any) |
|-------------|--------|:--------:|------------------------------------------|------------------------|
| **library** | string |    ✔     | Library path to the softHSM installation |                        |

#### AKV Configuration

| Name    | Type   | Required | Description      | Default Value (if any) |
|---------|--------|:--------:|------------------|------------------------|
| **url** | string |    ✔     | URL to AKV vault |                        |

### Server configuration

Request size limits applied to the REST and JSON-RPC entrypoints. Oversized requests are rejected before
unbounded allocation, mitigating unauthenticated memory-exhaustion attempts. A non-positive value for
either field is treated as unset and falls back to the default.

The 1 MiB body default comfortably fits a full batch of typical signing requests: a value-transfer
`eth_signTransaction` is a few hundred bytes, so a 100-element batch (the JSON-RPC batch element cap) is
roughly 50 KB. Because the body size scales with the batch element count, workloads that submit
large-calldata batches (for example contract deployments) may need a higher `maxRequestBodyBytes`.

| Name                    | Type | Required | Description                                                       | Default Value (if any) |
|-------------------------|------|:--------:|-------------------------------------------------------------------|------------------------|
| **maxRequestBodyBytes** | int  |    ✗     | Maximum accepted request body size in bytes, on REST and JSON-RPC | 1048576 (1 MiB)        |
| **maxHeaderBytes**      | int  |    ✗     | Maximum accepted request header size in bytes, on every server    | 1048576 (1 MiB)        |

## Command flags

When executing the Signare binary, a multitude of flags are at your disposal in order to customize some of its
configuration.

Let us delve deeper into the specifics to further describe the flag options:

| Name                     | Type   | Required | Description                                                  | Default Value (if any) |
|--------------------------|--------|:--------:|--------------------------------------------------------------|------------------------|
| **signer-administrator** | string |    ✔     | Id of Signare's initial admin                            |                        |
| **config**               | string |    ✔     | Path to where the config yml file is stored                  |                        |
| **listen-address**       | string |    ✗     | Address where Signare will listen                        | 0.0.0.0                |
| **http-port**            | int    |    ✗     | Number of the port where REST API methods will be hosted     | 32325                  |
| **rpc-port**             | int    |    ✗     | Number of the port where JSON RPC API methods will be hosted | 4545                   |




