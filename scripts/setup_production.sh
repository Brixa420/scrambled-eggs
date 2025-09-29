#!/bin/bash
set -e

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Update system
apt-get update
apt-get upgrade -y

# Install required packages
apt-get install -y \
    fail2ban \
    ufw \
    unattended-upgrades \
    apt-listchanges \
    curl \
    gnupg \
    ca-certificates \
    software-properties-common

# Configure automatic security updates
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOL'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOL

# Configure automatic reboots
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOL'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESM:${distro_codename}";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
Unattended-Upgrade::Automatic-Reboot-WithUsers "";
EOL

# Configure fail2ban
cat > /etc/fail2ban/jail.d/sshd.conf << 'EOL'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
findtime = 600
bantime = 3600
ignoreip = 127.0.0.1/8 ::1
EOL

# Configure UFW (Uncomplicated Firewall)
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw allow 5000/tcp  # App port
ufw allow 9090/tcp  # Prometheus
ufw allow 3000/tcp  # Grafana
ufw allow 9093/tcp  # Alertmanager
ufw enable

# Install Docker if not already installed
if ! command -v docker &> /dev/null; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io
    systemctl enable --now docker
fi

# Install Docker Compose if not already installed
if ! command -v docker-compose &> /dev/null; then
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
fi

# Create directory for application
mkdir -p /opt/scrambled-eggs
chown -R $SUDO_USER:$SUDO_USER /opt/scrambled-eggs

# Create backup directory
mkdir -p /var/backups/scrambled-eggs
chown -R $SUDO_USER:$SUDO_USER /var/backups/scrambled-eggs

# Create log directory
mkdir -p /var/log/scrambled-eggs
chown -R $SUDO_USER:$SUDO_USER /var/log/scrambled-eggs

# Create data directories
mkdir -p /data/scrambled-eggs/{postgres,redis,prometheus,grafana,alertmanager}
chown -R $SUDO_USER:$SUDO_USER /data/scrambled-eggs

# Set up log rotation
cat > /etc/logrotate.d/scrambled-eggs << 'EOL'
/var/log/scrambled-eggs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 $SUDO_USER $SUDO_USER
    sharedscripts
    postrotate
        docker-compose -f /opt/scrambled-eggs/docker-compose.prod.yml restart app > /dev/null
    endscript
}
EOL

# Set up daily backup script
cat > /usr/local/bin/backup-scrambled-eggs << 'EOL'
#!/bin/bash
set -e

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/var/backups/scrambled-eggs"
FILENAME="scrambled-eggs-backup-${TIMESTAMP}.sql.gz"

# Create backup
docker-compose -f /opt/scrambled-eggs/docker-compose.prod.yml exec -T db pg_dump -U $DB_USER $DB_NAME | gzip > "${BACKUP_DIR}/${FILENAME}"

# Keep only the last 7 backups
cd "$BACKUP_DIR" && ls -tp | grep -v '/$' | tail -n +8 | xargs -I {} rm -- {}

# Verify backup was created
if [ -f "${BACKUP_DIR}/${FILENAME}" ]; then
    echo "Backup created: ${BACKUP_DIR}/${FILENAME}"
else
    echo "Backup failed!"
    exit 1
fi
EOL

chmod +x /usr/local/bin/backup-scrambled-eggs

# Set up daily backup in crontab
if ! crontab -l | grep -q "backup-scrambled-eggs"; then
    (crontab -l 2>/dev/null; echo "0 3 * * * /usr/local/bin/backup-scrambled-eggs") | crontab -
fi

echo "Production setup completed successfully!"
echo "Please remember to:"
echo "1. Configure your .env file with production settings"
echo "2. Set up SSL certificates (e.g., using Let's Encrypt with Certbot)"
echo "3. Review and customize fail2ban settings in /etc/fail2ban/"
echo "4. Deploy your application to /opt/scrambled-eggs"
