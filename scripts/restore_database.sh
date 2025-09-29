#!/bin/bash

# Database restore script for Scrambled Eggs
# Usage: ./restore_database.sh [backup_file] [database_name]

set -euo pipefail

# Check if backup file is provided
if [ $# -lt 1 ]; then
    echo "Usage: $0 <backup_file> [database_name]"
    echo "Example: $0 /path/to/backup_file.sql.gz my_database"
    exit 1
fi

BACKUP_FILE="$1"
DB_NAME="${2:-scrambled_eggs}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="/var/log/scrambled-eggs/restore_${TIMESTAMP}.log"

# Ensure log directory exists
mkdir -p "$(dirname "${LOG_FILE}")"

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "${LOG_FILE}"
}

# Load environment variables if .env exists
if [ -f "$(dirname "$0")/../.env" ]; then
    export $(grep -v '^#' $(dirname "$0")/../.env | xargs)
fi

# Set database connection parameters
DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}
DB_USER=${DB_USER:-postgres}
DB_PASSWORD=${DB_PASSWORD:-}

# Check if backup file exists
if [ ! -f "${BACKUP_FILE}" ]; then
    log "ERROR: Backup file not found: ${BACKUP_FILE}"
    exit 1
fi

# Check if psql is available
if ! command -v psql &> /dev/null; then
    log "ERROR: psql command not found. Please ensure PostgreSQL client tools are installed."
    exit 1
fi

# Set PGPASSWORD if not already set
if [ -z "${PGPASSWORD}" ] && [ -n "${DB_PASSWORD}" ]; then
    export PGPASSWORD="${DB_PASSWORD}"
fi

# Check if the backup file is compressed
if [[ "${BACKUP_FILE}" == *.gz ]]; then
    COMPRESSED=true
    log "Detected gzipped backup file"
else
    COMPRESSED=false
fi

# Check if database exists
if ! psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -lqt | cut -d \| -f 1 | grep -qw "${DB_NAME}"; then
    log "Database '${DB_NAME}' does not exist. Creating..."
    if ! createdb -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" "${DB_NAME}"; then
        log "ERROR: Failed to create database '${DB_NAME}'"
        exit 1
    fi
fi

# Perform the restore
log "Starting restore of database: ${DB_NAME}"
log "Backup file: ${BACKUP_FILE}"

# Drop all objects in the database if it exists
echo "WARNING: This will drop all objects in the database '${DB_NAME}'. Are you sure? (y/n)"
read -r confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    log "Restore cancelled by user."
    exit 0
fi

log "Dropping all objects in database '${DB_NAME}'..."
echo "SELECT 'DROP ' || CASE 
    WHEN c.relkind = 'r' THEN 'TABLE' 
    WHEN c.relkind = 'v' THEN 'VIEW' 
    WHEN c.relkind = 'm' THEN 'MATERIALIZED VIEW' 
    WHEN c.relkind = 'i' THEN 'INDEX' 
    WHEN c.relkind = 'S' THEN 'SEQUENCE' 
    ELSE c.relkind::text 
END || ' IF EXISTS ' || n.nspname || '.' || c.relname || ' CASCADE;' 
FROM pg_class c 
JOIN pg_namespace n ON n.oid = c.relnamespace 
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') 
AND n.nspname NOT LIKE 'pg_%' 
AND c.relkind IN ('r', 'v', 'm', 'i', 'S');" | \
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t | \
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -f - 2>> "${LOG_FILE}"

# Restore the database
log "Restoring database from backup..."

if [ "$COMPRESSED" = true ]; then
    if ! gunzip -c "${BACKUP_FILE}" | pg_restore -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" --clean --if-exists --no-owner --no-privileges 2>> "${LOG_FILE}"; then
        log "ERROR: Restore failed. Check the log file for details: ${LOG_FILE}"
        exit 1
    fi
else
    if ! pg_restore -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" --clean --if-exists --no-owner --no-privileges "${BACKUP_FILE}" 2>> "${LOG_FILE}"; then
        log "ERROR: Restore failed. Check the log file for details: ${LOG_FILE}"
        exit 1
    fi
fi

log "Restore completed successfully."
log "Log file: ${LOG_FILE}"

exit 0
