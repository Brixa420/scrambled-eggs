#!/bin/bash

# Database backup script for Scrambled Eggs
# Usage: ./backup_database.sh [database_name] [backup_dir]

set -euo pipefail

# Default values
DB_NAME=${1:-scrambled_eggs}
BACKUP_DIR=${2:-/var/backups/scrambled-eggs}
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/${DB_NAME}_${TIMESTAMP}.sql.gz"
LOG_FILE="/var/log/scrambled-eggs/backup_${TIMESTAMP}.log"
KEEP_DAYS=30

# Ensure backup directory exists
mkdir -p "${BACKUP_DIR}"
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

# Check if pg_dump is available
if ! command -v pg_dump &> /dev/null; then
    log "ERROR: pg_dump command not found. Please ensure PostgreSQL client tools are installed."
    exit 1
fi

# Set PGPASSWORD if not already set
if [ -z "${PGPASSWORD}" ] && [ -n "${DB_PASSWORD}" ]; then
    export PGPASSWORD="${DB_PASSWORD}"
fi

# Create backup
log "Starting backup of database: ${DB_NAME}"
log "Backup file: ${BACKUP_FILE}"

# Perform the backup
if pg_dump -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" \
    --format=custom --blobs --verbose -f - 2>> "${LOG_FILE}" | gzip > "${BACKUP_FILE}"; then
    
    BACKUP_SIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
    log "Backup completed successfully. Size: ${BACKUP_SIZE}"
    
    # Set proper permissions
    chmod 600 "${BACKUP_FILE}"
    
    # Clean up old backups
    log "Cleaning up backups older than ${KEEP_DAYS} days..."
    find "${BACKUP_DIR}" -name "${DB_NAME}_*.sql.gz" -type f -mtime +${KEEP_DAYS} -delete -print | while read -r file; do
        log "Deleted old backup: ${file}"
    done
    
    # Verify the backup
    log "Verifying backup..."
    if gzip -t "${BACKUP_FILE}"; then
        log "Backup verification successful."
    else
        log "ERROR: Backup verification failed!"
        exit 1
    fi
    
    log "Backup process completed successfully."
    exit 0
else
    log "ERROR: Backup failed! Check the log file for details: ${LOG_FILE}"
    exit 1
fi
