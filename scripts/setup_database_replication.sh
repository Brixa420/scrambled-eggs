#!/bin/bash
set -e

# This script sets up PostgreSQL replication between a primary and standby server
# Usage: ./setup_database_replication.sh <primary_ip> <replica_ip> <replication_user> <replication_password>

if [ $# -ne 4 ]; then
    echo "Usage: $0 <primary_ip> <replica_ip> <replication_user> <replication_password>"
    exit 1
fi

PRIMARY_IP=$1
REPLICA_IP=$2
REPLICATION_USER=$3
REPLICATION_PASSWORD=$4
PRIVATE_IP=$(hostname -I | awk '{print $1}')

# Install PostgreSQL if not already installed
if ! command -v psql &> /dev/null; then
    apt-get update
    apt-get install -y postgresql postgresql-contrib
    systemctl start postgresql
    systemctl enable postgresql
fi

# Check if we're on the primary or replica
if [ "$PRIMARY_IP" = "$PRIVATE_IP" ]; then
    echo "Configuring primary database at $PRIMARY_IP..."
    
    # Configure postgresql.conf for primary
    sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" /etc/postgresql/*/main/postgresql.conf
    
    # Configure pg_hba.conf to allow replication
    echo "host    replication    ${REPLICATION_USER}    ${REPLICA_IP}/32    md5" >> /etc/postgresql/*/main/pg_hba.conf
    
    # Create replication user
    sudo -u postgres psql -c "CREATE USER ${REPLICATION_USER} WITH REPLICATION ENCRYPTED PASSWORD '${REPLICATION_PASSWORD}';"
    
    # Restart PostgreSQL
    systemctl restart postgresql
    
elif [ "$REPLICA_IP" = "$PRIVATE_IP" ]; then
    echo "Configuring replica database at $REPLICA_IP..."
    
    # Stop PostgreSQL
    systemctl stop postgresql
    
    # Backup existing data directory
    mv /var/lib/postgresql/*/main /var/lib/postgresql/$(ls /var/lib/postgresql)/main_backup_$(date +%Y%m%d)
    
    # Create base backup from primary
    PGPASSWORD=${REPLICATION_PASSWORD} pg_basebackup -h ${PRIMARY_IP} -D /var/lib/postgresql/$(ls /var/lib/postgresql)/main -U ${REPLICATION_USER} -v -P -X stream
    
    # Configure recovery.conf
    cat > /var/lib/postgresql/$(ls /var/lib/postgresql)/main/recovery.conf << EOL
standby_mode = 'on'
primary_conninfo = 'host=${PRIMARY_IP} port=5432 user=${REPLICATION_USER} password=${REPLICATION_PASSWORD}'
primary_slot_name = 'replica1_slot'
recovery_target_timeline = 'latest'
EOL
    
    # Set proper permissions
    chown -R postgres:postgres /var/lib/postgresql/$(ls /var/lib/postgresql)/main
    chmod 700 /var/lib/postgresql/$(ls /var/lib/postgresql)/main
    
    # Start PostgreSQL
    systemctl start postgresql
    
    # Create replication slot on primary
    ssh root@${PRIMARY_IP} "sudo -u postgres psql -c 'SELECT * FROM pg_create_physical_replication_slot(\"replica1_slot\");'"
    
else
    echo "This script should be run on either the primary or replica server."
    exit 1
fi

echo "Database replication setup complete!"
