-- Create shared user 'ztward' for both databases
CREATE USER ztward WITH PASSWORD 'ztward';

-- Create ztward_pap database
CREATE DATABASE ztward_pap;
GRANT ALL PRIVILEGES ON DATABASE ztward_pap TO ztward;

-- Create ztward_keymanager database
CREATE DATABASE ztward_keymanager;
GRANT ALL PRIVILEGES ON DATABASE ztward_keymanager TO ztward;
