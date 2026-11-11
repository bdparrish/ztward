# Database Integration Guide

Learn how to integrate Ztward with databases for policy storage, audit logging, and user attribute management.

## Table of Contents
- [Overview](#overview)
- [Configuration](#configuration)
- [Schema Setup](#schema-setup)
- [Policy Storage](#policy-storage)
- [Audit Logging](#audit-logging)
- [Performance Optimization](#performance-optimization)
- [High Availability](#high-availability)
- [Migration](#automated-migration)
- [Troubleshooting](#troubleshooting)

## Overview

Ztward uses databases for persistent storage of:

- **Policies**: JSON, OPA, and XACML policy definitions
- **Entitlements**: Access grants based on attributes
- **Audit Logs**: Authorization decisions and administrative actions
- **User Attributes**: Extended user profile information
- **Client Keys**: Encryption keys for ZTDF operations
- **Configuration**: System settings and metadata

**Benefits of Database Integration:**
- Persistent policy and entitlement storage
- Audit trail for compliance
- Scalable architecture
- High availability with replication
- Transaction support for consistency

## Configuration

### Database Connection String

Configure the database connection in your Ztward configuration file:

```yaml
# config.yaml
database:
  # PostgreSQL connection string
  connection_string: "postgresql://ztward:${DB_PASSWORD}@localhost:5432/ztward?sslmode=require"

  # Or use individual parameters
  host: "localhost"
  port: 5432
  database: "ztward"
  username: "ztward"
  password: "${DB_PASSWORD}"
  ssl_mode: "require"

  # Connection pool settings
  pool:
    max_connections: 25
    min_connections: 5
    max_idle_time: 300  # seconds
    connection_timeout: 10  # seconds

  # Performance settings
  statement_cache_size: 100
  max_prepared_statements: 1000

  # Retry settings
  retry:
    max_attempts: 3
    initial_backoff: 100ms
    max_backoff: 5s
```

### Environment Variables

Store sensitive credentials as environment variables:

```bash
# .env
DB_PASSWORD=your_secure_password_here
DB_HOST=ztward-db.example.com
DB_PORT=5432
DB_NAME=ztward
DB_USER=ztward
```

Then reference in configuration:

```yaml
database:
  host: "${DB_HOST}"
  port: "${DB_PORT}"
  database: "${DB_NAME}"
  username: "${DB_USER}"
  password: "${DB_PASSWORD}"
  ssl_mode: "require"
```

### SSL/TLS Configuration

For production deployments, always use SSL/TLS:

```yaml
database:
  connection_string: "postgresql://ztward:${DB_PASSWORD}@db.example.com:5432/ztward?sslmode=verify-full&sslrootcert=/path/to/ca.crt"

  # Or with parameters
  ssl_mode: "verify-full"  # require, verify-ca, verify-full
  ssl_root_cert: "/path/to/ca.crt"
  ssl_cert: "/path/to/client-cert.pem"
  ssl_key: "/path/to/client-key.pem"
```

**SSL Modes:**
- `disable`: No SSL (NOT for production!)
- `require`: Encrypt connection (no server verification)
- `verify-ca`: Encrypt and verify server certificate
- `verify-full`: Encrypt, verify certificate and hostname (recommended)

## Schema Setup

### Automated Migration

Ztward includes built-in database migrations. Run on first deployment:

```bash
# Run database migrations
ztward db migrate

# Or with custom config
ztward db migrate --config /path/to/config.yaml
```

This creates all required tables and indexes.

### Manual Schema Creation

If you need to create the schema manually:

```sql
-- 1. Create database
CREATE DATABASE ztward;

-- 2. Connect to database
\c ztward;

-- 3. Create schema
CREATE SCHEMA IF NOT EXISTS ztward;

-- 4. Create tables (see tables below)
```

### Core Tables

#### Policies Table

```sql
CREATE TABLE ztward.policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    effect VARCHAR(10) NOT NULL CHECK (effect IN ('allow', 'deny')),
    language VARCHAR(20) NOT NULL CHECK (language IN ('json', 'opa', 'xacml')),
    priority INTEGER NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT true,
    policy_content JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255),
    updated_by VARCHAR(255),
    metadata JSONB
);

-- Indexes
CREATE INDEX idx_policies_enabled ON ztward.policies(enabled) WHERE enabled = true;
CREATE INDEX idx_policies_priority ON ztward.policies(priority DESC);
CREATE INDEX idx_policies_language ON ztward.policies(language);
CREATE INDEX idx_policies_effect ON ztward.policies(effect);
CREATE INDEX idx_policies_content ON ztward.policies USING GIN (policy_content);
```

#### Entitlements Table

```sql
CREATE TABLE ztward.entitlements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    subject_attributes JSONB NOT NULL,
    resource_attributes JSONB NOT NULL,
    actions TEXT[] NOT NULL,
    conditions JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255),
    updated_by VARCHAR(255),
    metadata JSONB
);

-- Indexes
CREATE INDEX idx_entitlements_enabled ON ztward.entitlements(enabled) WHERE enabled = true;
CREATE INDEX idx_entitlements_subject_attrs ON ztward.entitlements USING GIN (subject_attributes);
CREATE INDEX idx_entitlements_resource_attrs ON ztward.entitlements USING GIN (resource_attributes);
CREATE INDEX idx_entitlements_actions ON ztward.entitlements USING GIN (actions);
```

#### Audit Logs Table

```sql
CREATE TABLE ztward.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    event_type VARCHAR(50) NOT NULL,
    user_id VARCHAR(255),
    subject_attributes JSONB,
    resource_id VARCHAR(255),
    resource_attributes JSONB,
    action VARCHAR(50),
    decision VARCHAR(20) CHECK (decision IN ('allow', 'deny')),
    policies_evaluated JSONB,
    entitlements_matched JSONB,
    reason TEXT,
    request_metadata JSONB,
    source_ip INET,
    user_agent TEXT
);

-- Indexes for performance
CREATE INDEX idx_audit_timestamp ON ztward.audit_logs(timestamp DESC);
CREATE INDEX idx_audit_user_id ON ztward.audit_logs(user_id);
CREATE INDEX idx_audit_resource_id ON ztward.audit_logs(resource_id);
CREATE INDEX idx_audit_decision ON ztward.audit_logs(decision);
CREATE INDEX idx_audit_event_type ON ztward.audit_logs(event_type);

-- Partial index for denied access (typically queried more)
CREATE INDEX idx_audit_denied ON ztward.audit_logs(timestamp DESC)
    WHERE decision = 'deny';
```

#### Client Keys Table

```sql
CREATE TABLE ztward.client_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) NOT NULL,
    key_type VARCHAR(50) NOT NULL,
    public_key BYTEA NOT NULL,
    encrypted_private_key BYTEA,  -- Null for public-key-only storage
    key_metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    revoked BOOLEAN NOT NULL DEFAULT false,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by VARCHAR(255)
);

-- Indexes
CREATE INDEX idx_client_keys_client_id ON ztward.client_keys(client_id);
CREATE INDEX idx_client_keys_active ON ztward.client_keys(client_id, expires_at)
    WHERE revoked = false AND (expires_at IS NULL OR expires_at > NOW());
CREATE INDEX idx_client_keys_expires ON ztward.client_keys(expires_at)
    WHERE expires_at IS NOT NULL AND revoked = false;
```

#### User Attributes Table (Optional)

For storing extended user attributes beyond OIDC claims:

```sql
CREATE TABLE ztward.user_attributes (
    user_id VARCHAR(255) PRIMARY KEY,
    attributes JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    synced_from VARCHAR(50),  -- e.g., 'oidc', 'ldap', 'manual'
    last_sync_at TIMESTAMP WITH TIME ZONE
);

-- Indexes
CREATE INDEX idx_user_attrs_attributes ON ztward.user_attributes USING GIN (attributes);
CREATE INDEX idx_user_attrs_updated ON ztward.user_attributes(updated_at DESC);
```

### Database Functions

#### Update Timestamp Trigger

Automatically update `updated_at` on record changes:

```sql
-- Create function
CREATE OR REPLACE FUNCTION ztward.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to policies table
CREATE TRIGGER update_policies_updated_at
    BEFORE UPDATE ON ztward.policies
    FOR EACH ROW
    EXECUTE FUNCTION ztward.update_updated_at_column();

-- Apply to entitlements table
CREATE TRIGGER update_entitlements_updated_at
    BEFORE UPDATE ON ztward.entitlements
    FOR EACH ROW
    EXECUTE FUNCTION ztward.update_updated_at_column();
```

## Policy Storage

### Storing Policies

Policies are stored in the `policies` table with JSONB content:

```sql
-- Insert JSON policy
INSERT INTO ztward.policies (
    name,
    description,
    effect,
    language,
    priority,
    policy_content
) VALUES (
    'Engineering Department Access',
    'Allow engineering staff to access engineering resources',
    'allow',
    'json',
    100,
    '{"conditions": {"subject": {"department": {"$eq": "engineering"}}}}'::jsonb
);

-- Insert OPA policy
INSERT INTO ztward.policies (
    name,
    effect,
    language,
    policy_content
) VALUES (
    'Clearance Check',
    'allow',
    'opa',
    '{"rego": "package ztward.authz\n\ndefault allow = false\n\nallow {\n    input.subject.clearance >= input.resource.classification\n}"}'::jsonb
);
```

### Querying Policies

```sql
-- Get all enabled policies sorted by priority
SELECT * FROM ztward.policies
WHERE enabled = true
ORDER BY priority DESC;

-- Get policies by language
SELECT * FROM ztward.policies
WHERE language = 'json' AND enabled = true;

-- Search policy content (JSONB queries)
SELECT * FROM ztward.policies
WHERE policy_content @> '{"conditions": {"subject": {"department": {"$eq": "engineering"}}}}';

-- Full-text search in policy names and descriptions
SELECT * FROM ztward.policies
WHERE to_tsvector('english', name || ' ' || COALESCE(description, ''))
    @@ to_tsquery('english', 'engineering & database');
```

## Audit Logging

### Logging Access Decisions

Every authorization request should be logged for audit purposes:

```sql
INSERT INTO ztward.audit_logs (
    event_type,
    user_id,
    subject_attributes,
    resource_id,
    resource_attributes,
    action,
    decision,
    policies_evaluated,
    entitlements_matched,
    reason,
    source_ip,
    user_agent
) VALUES (
    'authorization_request',
    'user123',
    '{"department": "engineering", "role": "engineer"}'::jsonb,
    'db-prod-01',
    '{"resource_type": "database", "owner": "engineering"}'::jsonb,
    'read',
    'allow',
    '["policy-123", "policy-456"]'::jsonb,
    '["ent-789"]'::jsonb,
    'Matched policy: Engineering Department Access',
    '192.168.1.100',
    'Mozilla/5.0...'
);
```

### Querying Audit Logs

```sql
-- Get recent access denials
SELECT timestamp, user_id, resource_id, action, reason
FROM ztward.audit_logs
WHERE decision = 'deny'
ORDER BY timestamp DESC
LIMIT 100;

-- Get all access for a specific user
SELECT timestamp, resource_id, action, decision
FROM ztward.audit_logs
WHERE user_id = 'user123'
ORDER BY timestamp DESC;

-- Get access to a specific resource
SELECT timestamp, user_id, action, decision, reason
FROM ztward.audit_logs
WHERE resource_id = 'db-prod-01'
ORDER BY timestamp DESC;

-- Get statistics by decision
SELECT decision, COUNT(*) as count
FROM ztward.audit_logs
WHERE timestamp >= NOW() - INTERVAL '24 hours'
GROUP BY decision;

-- Get most frequently denied users (potential security issues)
SELECT user_id, COUNT(*) as denied_count
FROM ztward.audit_logs
WHERE decision = 'deny'
    AND timestamp >= NOW() - INTERVAL '7 days'
GROUP BY user_id
ORDER BY denied_count DESC
LIMIT 10;
```

### Audit Log Retention

Implement retention policies to manage audit log growth:

```sql
-- Delete audit logs older than 90 days
DELETE FROM ztward.audit_logs
WHERE timestamp < NOW() - INTERVAL '90 days';

-- Archive to separate table before deletion
INSERT INTO ztward.audit_logs_archive
SELECT * FROM ztward.audit_logs
WHERE timestamp < NOW() - INTERVAL '90 days';

-- Then delete
DELETE FROM ztward.audit_logs
WHERE timestamp < NOW() - INTERVAL '90 days';
```

Create a scheduled job (cron or pg_cron) to run periodically:

```sql
-- Using pg_cron extension
CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Schedule daily cleanup at 2 AM
SELECT cron.schedule(
    'audit-log-cleanup',
    '0 2 * * *',
    $$DELETE FROM ztward.audit_logs WHERE timestamp < NOW() - INTERVAL '90 days'$$
);
```

## Performance Optimization

### Indexing Strategy

Ensure appropriate indexes exist for common queries:

```sql
-- Policy queries
CREATE INDEX CONCURRENTLY idx_policies_enabled_priority
    ON ztward.policies(enabled, priority DESC)
    WHERE enabled = true;

-- Audit log time-series queries
CREATE INDEX CONCURRENTLY idx_audit_logs_timestamp_decision
    ON ztward.audit_logs(timestamp DESC, decision);

-- User-specific audit queries
CREATE INDEX CONCURRENTLY idx_audit_logs_user_timestamp
    ON ztward.audit_logs(user_id, timestamp DESC);

-- JSONB attribute searches
CREATE INDEX CONCURRENTLY idx_policies_content_gin
    ON ztward.policies USING GIN (policy_content jsonb_path_ops);
```

### Query Optimization

Use EXPLAIN ANALYZE to optimize slow queries:

```sql
-- Check query plan
EXPLAIN ANALYZE
SELECT * FROM ztward.policies
WHERE enabled = true
ORDER BY priority DESC;

-- Optimize with covering index
CREATE INDEX idx_policies_covering
    ON ztward.policies(enabled, priority DESC)
    INCLUDE (id, name, effect, language, policy_content)
    WHERE enabled = true;
```

### Connection Pooling

Use connection pooling to reduce connection overhead:

```yaml
database:
  pool:
    max_connections: 25      # Maximum connections in pool
    min_connections: 5       # Minimum idle connections
    max_idle_time: 300       # Close idle connections after 5 minutes
    connection_timeout: 10   # Timeout for acquiring connection
```

**Recommended Pool Sizes:**
- Small deployment: 10-25 connections
- Medium deployment: 25-50 connections
- Large deployment: 50-100 connections

Formula: `max_connections = (cpu_cores * 2) + disk_spindles`

### Table Partitioning

For large audit log tables, use partitioning:

```sql
-- Create partitioned audit log table
CREATE TABLE ztward.audit_logs_partitioned (
    id UUID DEFAULT gen_random_uuid(),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    user_id VARCHAR(255),
    decision VARCHAR(20),
    -- ... other columns
) PARTITION BY RANGE (timestamp);

-- Create monthly partitions
CREATE TABLE ztward.audit_logs_2025_01
    PARTITION OF ztward.audit_logs_partitioned
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

CREATE TABLE ztward.audit_logs_2025_02
    PARTITION OF ztward.audit_logs_partitioned
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');

-- Create indexes on partitions
CREATE INDEX idx_audit_2025_01_timestamp
    ON ztward.audit_logs_2025_01(timestamp DESC);
```

### Vacuum and Analyze

Regularly maintain table statistics:

```sql
-- Manual vacuum
VACUUM ANALYZE ztward.policies;
VACUUM ANALYZE ztward.audit_logs;

-- Enable autovacuum (default, but verify)
ALTER TABLE ztward.audit_logs SET (autovacuum_enabled = true);
```

## High Availability

### Read Replicas

Configure read replicas for scaling read operations:

```yaml
database:
  # Primary database (read-write)
  primary:
    host: "primary.db.example.com"
    port: 5432
    connection_string: "postgresql://ztward:${DB_PASSWORD}@primary.db.example.com:5432/ztward"

  # Read replicas (read-only)
  replicas:
    - host: "replica1.db.example.com"
      port: 5432
      connection_string: "postgresql://ztward:${DB_PASSWORD}@replica1.db.example.com:5432/ztward"

    - host: "replica2.db.example.com"
      port: 5432
      connection_string: "postgresql://ztward:${DB_PASSWORD}@replica2.db.example.com:5432/ztward"

  # Read distribution strategy
  read_strategy: "round-robin"  # or "random", "least-connections"
```

**Use read replicas for:**
- Policy queries (policies rarely change)
- Audit log queries
- Reporting and analytics

**Use primary for:**
- Policy writes (create, update, delete)
- Audit log writes
- Entitlement modifications

### Connection Failover

Configure automatic failover:

```yaml
database:
  failover:
    enabled: true
    max_retry_attempts: 3
    retry_interval: 5s
    health_check_interval: 30s

  # List hosts in priority order
  hosts:
    - "primary.db.example.com:5432"
    - "standby1.db.example.com:5432"
    - "standby2.db.example.com:5432"
```

### Backup and Recovery

Implement regular backups:

```bash
# Automated backup script
#!/bin/bash

BACKUP_DIR="/backups/ztward"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/ztward_$TIMESTAMP.sql.gz"

# Create backup
pg_dump -h localhost -U ztward -d ztward | gzip > "$BACKUP_FILE"

# Verify backup
gunzip -t "$BACKUP_FILE"

# Upload to S3 (optional)
aws s3 cp "$BACKUP_FILE" "s3://backups/ztward/"

# Delete local backups older than 7 days
find "$BACKUP_DIR" -name "ztward_*.sql.gz" -mtime +7 -delete
```

Schedule with cron:

```bash
# Daily backup at 1 AM
0 1 * * * /usr/local/bin/backup-ztward-db.sh
```

## Troubleshooting

### Connection Issues

**Error**: `connection refused` or `timeout`

**Solutions:**

1. **Check network connectivity**:
   ```bash
   # Test connection
   telnet db.example.com 5432

   # Or with nc
   nc -zv db.example.com 5432
   ```

2. **Verify PostgreSQL is running**:
   ```bash
   # On database server
   systemctl status postgresql
   ```

3. **Check firewall rules**:
   ```bash
   # Allow PostgreSQL port
   sudo ufw allow 5432/tcp
   ```

4. **Verify pg_hba.conf**:
   ```
   # Allow connections from Ztward servers
   host    ztward    ztward    10.0.0.0/8    md5
   ```

### Authentication Failures

**Error**: `password authentication failed`

**Solutions:**

1. **Verify credentials**:
   ```bash
   # Test with psql
   psql -h db.example.com -U ztward -d ztward
   ```

2. **Check password in environment**:
   ```bash
   echo $DB_PASSWORD
   ```

3. **Verify user exists**:
   ```sql
   SELECT usename FROM pg_user WHERE usename = 'ztward';
   ```

### Slow Queries

**Problem**: Database queries taking too long

**Solutions:**

1. **Identify slow queries**:
   ```sql
   -- Enable query logging
   ALTER SYSTEM SET log_min_duration_statement = 1000;  -- Log queries > 1s
   SELECT pg_reload_conf();

   -- Check pg_stat_statements
   SELECT query, calls, total_time, mean_time
   FROM pg_stat_statements
   ORDER BY mean_time DESC
   LIMIT 10;
   ```

2. **Add missing indexes**:
   ```sql
   -- Check for missing indexes
   SELECT schemaname, tablename, attname, n_distinct, correlation
   FROM pg_stats
   WHERE schemaname = 'ztward'
   ORDER BY abs(correlation) DESC;
   ```

3. **Update statistics**:
   ```sql
   ANALYZE ztward.policies;
   ANALYZE ztward.audit_logs;
   ```

### Table Bloat

**Problem**: Tables growing too large due to dead tuples

**Solutions:**

```sql
-- Check table bloat
SELECT schemaname, tablename,
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size,
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename) - pg_relation_size(schemaname||'.'||tablename)) AS index_size
FROM pg_tables
WHERE schemaname = 'ztward'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Vacuum to reclaim space
VACUUM FULL ztward.audit_logs;

-- Or just analyze (less disruptive)
VACUUM ANALYZE ztward.audit_logs;
```

## Security Best Practices

### 1. Use Dedicated Database User

Create a dedicated user for Ztward:

```sql
-- Create user
CREATE USER ztward WITH PASSWORD 'secure_password_here';

-- Grant minimal privileges
GRANT CONNECT ON DATABASE ztward TO ztward;
GRANT USAGE ON SCHEMA ztward TO ztward;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ztward TO ztward;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ztward TO ztward;
```

### 2. Enable SSL/TLS

Always use encrypted connections:

```yaml
database:
  ssl_mode: "verify-full"
  ssl_root_cert: "/path/to/ca.crt"
```

### 3. Rotate Credentials Regularly

Change database passwords periodically:

```sql
-- Change password
ALTER USER ztward WITH PASSWORD 'new_secure_password';
```

### 4. Audit Database Access

Enable PostgreSQL audit logging:

```conf
# postgresql.conf
log_connections = on
log_disconnections = on
log_statement = 'ddl'  # Log DDL statements
```

### 5. Backup Encryption

Encrypt backups:

```bash
# Encrypted backup
pg_dump -h localhost -U ztward -d ztward | \
    gzip | \
    openssl enc -aes-256-cbc -salt -out ztward_backup.sql.gz.enc
```

## Next Steps

- [Secrets Manager Integration](./SECRETS_MANAGER.md)
- [Key Manager Integration](./KEY_MANAGER.md)
- [OIDC Integration](./OIDC_INTEGRATION.md)
- [Create Policies](../policies/JSON_POLICIES.md)

## License

Copyright © 2026 Benjamin Parrish
