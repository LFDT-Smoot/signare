-- Create a dedicated low-privilege role that owns the Signare database instead of using the postgres
-- superuser. The role's password must be supplied as the psql variable 'signare_password', for example:
--   psql -U postgres -v signare_password="$SIGNARE_DATABASE_POSTGRESQL_PASSWORD" -f create-databases.sql

-- Abort before creating anything unless signare_password was provided. Without this guard an unset
-- variable could leave a login role with an empty password: ON_ERROR_STOP would not catch it because
-- assigning an empty password is not itself an error. This existence test does not depend on how psql
-- substitutes an unset variable.
\if :{?signare_password}
\else
\echo 'ERROR: psql variable signare_password is not set. Pass -v signare_password=<password> (see configure-postgres.sh).'
\quit
\endif

DO
$$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'signare') THEN
      CREATE ROLE signare LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
   END IF;
END
$$;
ALTER ROLE signare WITH PASSWORD :'signare_password';

DROP DATABASE IF EXISTS db_signare;
CREATE DATABASE db_signare
WITH OWNER = signare
     ENCODING = 'UTF8'
     TABLESPACE = pg_default
     CONNECTION LIMIT = -1;
ALTER DATABASE db_signare WITH CONNECTION LIMIT = -1;

-- Give the signare role full control of the schema it will populate. The migrations connect as the
-- signare role and create the tables, so the role must own the public schema of its database.
\connect db_signare
ALTER SCHEMA public OWNER TO signare;
