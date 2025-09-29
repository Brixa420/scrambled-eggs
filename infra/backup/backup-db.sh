#!/bin/bash

# Configuration
BACKUP_DIR="/backups/db"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
FILENAME="db_backup_${TIMESTAMP}.sql.gz"
RETENTION_DAYS=30

# Ensure backup directory exists
mkdir -p "${BACKUP_DIR}"

# Dump database and compress
PGPASSWORD="${DB_PASSWORD}" pg_dump -h ${DB_HOST} -U ${DB_USER} -d ${DB_NAME} | gzip > "${BACKUP_DIR}/${FILENAME}"

# Remove old backups
find "${BACKUP_DIR}" -name "db_backup_*.sql.gz" -type f -mtime +${RETENTION_DAYS} -delete

# Sync to S3 (if configured)
if [ -n "${S3_BUCKET}" ]; then
  aws s3 sync "${BACKUP_DIR}" "s3://${S3_BUCKET}/db-backups/$(hostname)" --delete
fi

echo "Backup completed: ${BACKUP_DIR}/${FILENAME}"
