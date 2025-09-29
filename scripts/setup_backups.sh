#!/bin/bash
set -e

# Create backup directory
BACKUP_DIR="/var/backups/scrambled-eggs"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# Create backup script
cat > /usr/local/bin/backup-scrambled-eggs << 'EOL'
#!/bin/bash
set -e

# Load environment variables
if [ -f /opt/scrambled-eggs/.env ]; then
    export $(grep -v '^#' /opt/scrambled-eggs/.env | xargs)
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/var/backups/scrambled-eggs"
ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:-}"
FILENAME="scrambled-eggs-backup-${TIMESTAMP}.sql"

# Create backup
echo "Creating database backup..."
docker-compose -f /opt/scrambled-eggs/docker-compose.prod.yml exec -T db pg_dump -U $DB_USER $DB_NAME > "${BACKUP_DIR}/${FILENAME}"

# Compress backup
gzip "${BACKUP_DIR}/${FILENAME}"

# Encrypt backup if encryption key is set
if [ -n "$ENCRYPTION_KEY" ]; then
    echo "Encrypting backup..."
    openssl enc -aes-256-cbc -salt -in "${BACKUP_DIR}/${FILENAME}.gz" -out "${BACKUP_DIR}/${FILENAME}.gz.enc" -pass pass:${ENCRYPTION_KEY}
    rm "${BACKUP_DIR}/${FILENAME}.gz"
    FILENAME="${FILENAME}.gz.enc"
else
    FILENAME="${FILENAME}.gz"
fi

# Upload to S3 if configured
if [ -n "$AWS_ACCESS_KEY_ID" ] && [ -n "$AWS_SECRET_ACCESS_KEY" ] && [ -n "$S3_BUCKET" ]; then
    echo "Uploading backup to S3..."
    export AWS_ACCESS_KEY_ID
    export AWS_SECRET_ACCESS_KEY
    aws s3 cp "${BACKUP_DIR}/${FILENAME}" "s3://${S3_BUCKET}/scrambled-eggs/backups/"
fi

# Keep only the last 7 backups locally
echo "Rotating backups..."
cd "$BACKUP_DIR" && ls -tp | grep -v '/$' | tail -n +8 | xargs -I {} rm -- {}

# Verify backup was created
if [ -f "${BACKUP_DIR}/${FILENAME}" ]; then
    echo "Backup created: ${BACKUP_DIR}/${FILENAME}"
    exit 0
else
    echo "Backup failed!"
    exit 1
fi
EOL

# Make backup script executable
chmod +x /usr/local/bin/backup-scrambled-eggs

# Set up daily backup in crontab
if ! crontab -l | grep -q "backup-scrambled-eggs"; then
    (crontab -l 2>/dev/null; echo "0 3 * * * /usr/local/bin/backup-scrambled-eggs") | crontab -
fi

# Create restore script
cat > /usr/local/bin/restore-scrambled-eggs << 'EOL'
#!/bin/bash
set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <backup_file>"
    echo "Available backups:"
    ls -l /var/backups/scrambled-eggs/
    exit 1
fi

BACKUP_FILE="$1"
FULL_PATH="/var/backups/scrambled-eggs/${BACKUP_FILE}"

if [ ! -f "$FULL_PATH" ]; then
    echo "Error: Backup file not found: $FULL_PATH"
    exit 1
fi

# Load environment variables
if [ -f /opt/scrambled-eggs/.env ]; then
    export $(grep -v '^#' /opt/scrambled-eggs/.env | xargs)
fi

# Check if the file is encrypted
if [[ "$BACKUP_FILE" == *.enc ]]; then
    if [ -z "$BACKUP_ENCRYPTION_KEY" ]; then
        echo "Error: Backup is encrypted but no BACKUP_ENCRYPTION_KEY is set"
        exit 1
    fi
    
    echo "Decrypting backup..."
    DECRYPTED_FILE="${FULL_PATH%.enc}"
    openssl enc -d -aes-256-cbc -in "$FULL_PATH" -out "$DECRYPTED_FILE" -pass pass:${BACKUP_ENCRYPTION_KEY}
    FULL_PATH="$DECRYPTED_FILE"
fi

# Check if the file is compressed
if [[ "$FULL_PATH" == *.gz ]]; then
    echo "Decompressing backup..."
    gunzip -c "$FULL_PATH" | docker-compose -f /opt/scrambled-eggs/docker-compose.prod.yml exec -T db psql -U $DB_USER -d $DB_NAME
else
    cat "$FULL_PATH" | docker-compose -f /opt/scrambled-eggs/docker-compose.prod.yml exec -T db psql -U $DB_USER -d $DB_NAME
fi

echo "Database restore completed successfully!"
EOL

# Make restore script executable
chmod +x /usr/local/bin/restore-scrambled-eggs

echo "Backup system setup complete!"
echo "Backups will run daily at 3 AM"
echo "To manually create a backup: backup-scrambled-eggs"
echo "To restore from a backup: restore-scrambled-eggs <backup_file>"
