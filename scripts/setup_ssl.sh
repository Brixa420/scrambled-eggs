#!/bin/bash
set -e

# Install certbot if not already installed
if ! command -v certbot &> /dev/null; then
    apt-get update
    apt-get install -y certbot python3-certbot-nginx
fi

# Stop Nginx temporarily
systemctl stop nginx

# Obtain SSL certificate
certbot certonly --standalone \
    --non-interactive \
    --agree-tos \
    --email admin@scrambled-eggs.com \
    -d scrambled-eggs.com \
    -d www.scrambled-eggs.com \
    --preferred-challenges http \
    --expand

# Set up automatic renewal
(crontab -l 2>/dev/null; echo "0 0,12 * * * root python3 -c 'import random; import time; time.sleep(random.random() * 3600)' && certbot renew --quiet") | crontab -

# Restart Nginx
systemctl start nginx

echo "SSL certificate setup complete!"
echo "You can test the renewal with: certbot renew --dry-run"
