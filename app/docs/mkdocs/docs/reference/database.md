# Database reference

This document covers supported database technologies, authentication mechanisms, database schema and recommendations.

The target audience of this document are developers, system administrators and database administrators.

The application static configuration file options to connect to the database are out of scope of this document. Please, check [the configuration reference](./configuration.md){:target="_blank"} for details about the application static configuration.

## Supported database technologies

The application supports [PostgreSQL](https://www.postgresql.org/){:target="_blank"} as the database technology.

!!! note

    SQLite is also supported but just for testing purposes.

## Authentication mechanisms

User credentials (user and password) is the supported authentication mechanism for PostgreSQL. There are several password-based authentication methods in PostgreSQL, but ``scram-sha-256`` is the most secure one of them and therefore the one recommended to use. This configuration should be done on the server.

In addition to the above-mentioned authentication mechanism and even though it is a challenge-response scheme that prevents password sniffing on untrusted connections, the signare also supports SSL/TLS connections so that all the traffic between the client and the server is sent encrypted.

More precisely, the application supports the following SSL modes:

- **disable**: TLS mode is disabled.
- **require**: TLS mode is enabled, but no certificate validation is done.
- **verify-ca**: TLS mode is enabled, check the certificate chain up to a trusted certificate authority (CA).
- **verify-full**: TLS mode is enabled, check certificate chain and verify server host name matches its certificate. This is the most secure one.

The signare currently does not support custom locations for specifying the CA certificate, so if adding non-public or untrusted certificates, they must be installed to the operating system’s trusted chain. This is operating system specific.

## Encryption

The application does not store HSM slot PINs. A slot records the name of the file holding its PIN (see [`pinSourceDirectory`](./configuration.md#softhsm-configuration)), and the value is read from that file at login time.

The `pin` column of `cfg_hardware_security_module_slot` has been dropped.

**Every slot must resolve its PIN from a source before upgrading to this release.** There is no fallback: a slot with no `pinSource` fails every signing request until one is set, and Signare cannot recover the PIN for you. Migration `000005` refuses the upgrade while any slot still holds a stored PIN and names no source, so a deployment that has not moved its slots fails the upgrade instead of losing the credential.

If the upgrade is refused:

1. For each slot the error names, write its PIN into the configured `pinSourceDirectory` and point the slot at the file with `admin.slots.updatePinSource`, running the previous release.
2. Clear the dirty flag the aborted migration left behind: `UPDATE signare_migrations SET dirty = false WHERE version = 5`. `signare upgrade` refuses to run while a version is marked dirty.
3. Run `signare upgrade` again.

**Any PIN written before the column was dropped must be rotated on the token.** Dropping a column in PostgreSQL only updates the catalog, so the value stays in the existing heap tuples until those rows are rewritten; `VACUUM FULL cfg_hardware_security_module_slot` or `pg_repack` does that. Even then the value survives in WAL archives and in every backup taken while it was stored, which is why rotation on the token, not this migration, is what actually retires a PIN.

The database still holds Local Key Vault private key material, and Local Key Vault is not for production use. In addition to using a secure SSL mode for the connection between the application and the database server, we recommend using encryption at rest. Please, refer to the Data Partition Encryption section of PostgreSQL's encryption options [documentation](https://www.postgresql.org/docs/current/encryption-options.html){:target="_blank"}.

## Schema

The signare doesn't use database foreign keys. It's the application's logic that manages relations between tables/resources.

### Resources relations

In order to better understand the relationship between signare resources you can take a look at this diagram depicting them: 


<figure markdown="span">
```puml
@startuml

Application --|> User : N
Application --|> Slot : 1
User --|> Account : N
User --|> Application : 1
Module --|> Slot : N

Admin -[hidden]-> Admin

@enduml
```
  <figcaption>signare resources relationship diagram</figcaption>
</figure>

