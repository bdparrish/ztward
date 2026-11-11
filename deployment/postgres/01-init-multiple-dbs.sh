#!/bin/bash
set -e
set -u

# Function to create a database and user if they don't exist
function create_user_and_database() {
	local database=$1
	local user=$2
	local password=$3
	echo "  Creating user '$user' and database '$database'"
	psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
	    CREATE USER $user WITH PASSWORD '$password';
	    CREATE DATABASE $database;
	    GRANT ALL PRIVILEGES ON DATABASE $database TO $user;
	    \c $database
	    GRANT ALL ON SCHEMA public TO $user;
EOSQL
}

# Create ztward user (shared by both databases)
echo "  Creating shared user 'ztward'"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE USER ztward WITH PASSWORD 'ztward';
EOSQL

# Create ztward_pap database
echo "  Creating database 'ztward_pap'"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE DATABASE ztward_pap;
    GRANT ALL PRIVILEGES ON DATABASE ztward_pap TO ztward;
    \c ztward_pap
    GRANT ALL ON SCHEMA public TO ztward;
EOSQL

# Create ztward_keymanager database
echo "  Creating database 'ztward_keymanager'"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE DATABASE ztward_keymanager;
    GRANT ALL PRIVILEGES ON DATABASE ztward_keymanager TO ztward;
    \c ztward_keymanager
    GRANT ALL ON SCHEMA public TO ztward;
EOSQL

echo "Multiple databases created successfully"
