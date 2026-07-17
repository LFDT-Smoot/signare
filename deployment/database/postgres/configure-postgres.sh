#!/usr/bin/env bash
set -e

CONTAINER_NAME="postgres_10_12"

# Container name expected as an env variable
if [[ "${SIGNARE_POSTGRES_CONTAINER_NAME}" != "" ]]
then
	CONTAINER_NAME="${SIGNARE_POSTGRES_CONTAINER_NAME}"
fi

# Superuser password for the bootstrap connection. It is no longer hardcoded: supply it via the
# environment. This is the postgres superuser, used only to create the database and the signare role.
: "${PGPASSWORD:?set PGPASSWORD to the postgres superuser password}"
# Password assigned to the low-privilege signare role that owns the database and that the Signare
# service authenticates with at runtime (the same value as SIGNARE_DATABASE_POSTGRESQL_PASSWORD).
: "${SIGNARE_DATABASE_POSTGRESQL_PASSWORD:?set SIGNARE_DATABASE_POSTGRESQL_PASSWORD for the signare DB role}"

docker cp create-databases.sql "${CONTAINER_NAME}":/
docker exec -e PGPASSWORD="${PGPASSWORD}" -i "${CONTAINER_NAME}" \
	psql -U postgres -a -v ON_ERROR_STOP=1 \
	-v signare_password="${SIGNARE_DATABASE_POSTGRESQL_PASSWORD}" \
	-f /create-databases.sql
