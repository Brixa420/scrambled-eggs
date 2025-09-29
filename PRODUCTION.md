# Scrambled Eggs - Production Deployment Guide

This guide provides comprehensive instructions for deploying Scrambled Eggs in a production environment.

## 🚀 Prerequisites

- Ubuntu 20.04/22.04 LTS server
- Root access or sudo privileges
- Domain name (recommended)
- Minimum server specs:
  - 2 CPU cores
  - 4GB RAM (8GB recommended)
  - 50GB+ disk space (SSD recommended)

## 🔧 Server Setup

### 1. Initial Server Configuration

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y git curl wget ufw fail2ban unattended-upgrades \
    apt-transport-https ca-certificates software-properties-common

# Configure firewall
sudo ufw allow OpenSSH
sudo ufw allow http
sudo ufw allow https
sudo ufw enable

# Enable automatic security updates
sudo dpkg-reconfigure -plow unattended-upgrades
```

### 2. Install Docker and Docker Compose

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add current user to docker group
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Verify installation
docker --version
docker-compose --version
```

## 📦 Application Deployment

### 1. Clone the Repository

```bash
# Create app directory
sudo mkdir -p /opt/scrambled-eggs
sudo chown $USER:$USER /opt/scrambled-eggs

# Clone the repository
cd /opt/scrambled-eggs
git clone https://github.com/yourusername/scrambled-eggs.git .
```

### 2. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Generate secure keys
sed -i "s/SECRET_KEY=.*/SECRET_KEY=$(openssl rand -hex 32)/" .env
sed -i "s/ENCRYPTION_KEY=.*/ENCRYPTION_KEY=$(openssl rand -hex 32)/" .env
sed -i "s/JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$(openssl rand -hex 32)/" .env

# Edit other environment variables as needed
nano .env
```

### 3. Set Up SSL with Let's Encrypt

```bash
# Install certbot
sudo apt install -y certbot python3-certbot-nginx

# Stop any running web server
sudo systemctl stop nginx

# Get certificate
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com --non-interactive --agree-tos -m your-email@example.com

# Set up automatic renewal
echo "0 0,12 * * * root python3 -c 'import random; import time; time.sleep(random.random() * 3600)' && certbot renew -q" | sudo tee -a /etc/cron.d/certbot > /dev/null
```

### 4. Configure Nginx

```bash
# Install Nginx
sudo apt install -y nginx

# Create Nginx config
sudo nano /etc/nginx/sites-available/scrambled-eggs
```

Paste the following configuration (adjust domain names as needed):

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval';" always;

    # Proxy to application
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the site and restart Nginx:

```bash
sudo ln -s /etc/nginx/sites-available/scrambled-eggs /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 5. Set Up Systemd Service

```bash
# Create systemd service file
sudo nano /etc/systemd/system/scrambled-eggs.service
```

Paste the following:

```ini
[Unit]
Description=Scrambled Eggs Application
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/scrambled-eggs
Environment="PATH=/usr/local/bin"
ExecStart=/usr/local/bin/docker-compose up --build
ExecStop=/usr/local/bin/docker-compose down
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable scrambled-eggs
sudo systemctl start scrambled-eggs
```

## 🔒 Security Hardening

### 1. Configure Fail2Ban

```bash
# Configure SSH jail
sudo nano /etc/fail2ban/jail.local
```

Add the following:

```ini
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = %(sshd_log)s
maxretry = 5
bantime = 1h
findtime = 1h

[scrambled-eggs]
enabled = true
port = http,https
filter = scrambled-eggs
logpath = /var/log/nginx/access.log
maxretry = 10
bantime = 1h
findtime = 1h
```

Create the filter:

```bash
sudo nano /etc/fail2ban/filter.d/scrambled-eggs.conf
```

Add:

```ini
[Definition]
failregex = ^<HOST>.*"(GET|POST|HEAD).*" (404|444|403|400|401|429) .*$
ignoreregex =
```

Restart Fail2Ban:

```bash
sudo systemctl restart fail2ban
```

### 2. Set Up Automatic Security Updates

```bash
# Configure automatic updates
sudo dpkg-reconfigure -plow unattended-upgrades

# Edit configuration
sudo nano /etc/apt/apt.conf.d/50unattended-upgrades
```

Make sure the following lines are present:

```
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
```

## 📊 Monitoring and Logging

### 1. Set Up Log Rotation

```bash
# Configure log rotation
sudo nano /etc/logrotate.d/scrambled-eggs
```

Add:

```
/opt/scrambled-eggs/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 www-data www-data
    sharedscripts
    postrotate
        systemctl restart scrambled-eggs
    endscript
}
```

### 2. Monitor Application Logs

```bash
# View logs in real-time
sudo journalctl -u scrambled-eggs -f

# View Nginx access logs
sudo tail -f /var/log/nginx/access.log

# View Nginx error logs
sudo tail -f /var/log/nginx/error.log
```

## 🔄 Backup and Recovery

### 1. Database Backups

Create a backup script:

```bash
nano /opt/scrambled-eggs/scripts/backup-db.sh
```

Add:

```bash
#!/bin/bash

# Load environment variables
cd /opt/scrambled-eggs
source .env

# Create backup directory
BACKUP_DIR="/var/backups/scrambled-eggs"
mkdir -p $BACKUP_DIR

# Create backup filename
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/db_backup_$TIMESTAMP.sql.gz"

# Dump and compress database
docker-compose exec -T db pg_dump -U $POSTGRES_USER $POSTGRES_DB | gzip > $BACKUP_FILE

# Keep only the last 7 backups
find $BACKUP_DIR -type f -name "db_backup_*.sql.gz" | sort -r | tail -n +8 | xargs --no-run-if-empty rm --

echo "Backup created: $BACKUP_FILE"
```

Make it executable and test:

```bash
chmod +x /opt/scrambled-eggs/scripts/backup-db.sh
/opt/scrambled-eggs/scripts/backup-db.sh
```

### 2. Schedule Automatic Backups

```bash
# Add to crontab
(crontab -l 2>/dev/null; echo "0 3 * * * /opt/scrambled-eggs/scripts/backup-db.sh") | crontab -
```

## 🔄 Updating the Application

```bash
# Stop the service
sudo systemctl stop scrambled-eggs

# Pull latest changes
cd /opt/scrambled-eggs
git pull

# Rebuild and start
sudo systemctl start scrambled-eggs

# View logs to monitor startup
sudo journalctl -u scrambled-eggs -f
```

## 🆘 Troubleshooting

### Common Issues

1. **Port already in use**
   ```bash
   sudo lsof -i :80
   sudo lsof -i :443
   sudo lsof -i :5000
   ```

2. **Docker issues**
   ```bash
   # Check container logs
   docker-compose logs -f
   
   # Rebuild containers
   docker-compose down
   docker-compose up --build -d
   ```

3. **Nginx issues**
   ```bash
   # Test Nginx configuration
   sudo nginx -t
   
   # Check error logs
   sudo tail -f /var/log/nginx/error.log
   ```

## 📞 Support

For support, please open an issue on our [GitHub repository](https://github.com/yourusername/scrambled-eggs/issues).

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
