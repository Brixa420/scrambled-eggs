#!/bin/bash
set -e

# Generate or renew SSL certificate
if [ ! -f "/etc/letsencrypt/live/scrambled-eggs.com/fullchain.pem" ]; then
    certbot certonly --standalone --non-interactive --agree-tos \
        --email admin@scrambled-eggs.com \
        --domains scrambled-eggs.com \
        --preferred-challenges http \
        --http-01-port 80
fi

# Update TURN server configuration with actual IP
CURRENT_IP=$(curl -s https://api.ipify.org)
sed -i "s/YOUR_SERVER_IP/$CURRENT_IP/g" /etc/coturn/turnserver.conf

# Generate long-term credentials
if [ -z "$TURN_SECRET" ]; then
    export TURN_SECRET=$(openssl rand -hex 32)
fi

echo "TURN server secret: $TURN_SECRET"

# Start TURN server
exec /usr/local/bin/turnserver -c /etc/coturn/turnserver.conf --log-file /var/log/coturn/turnserver.log

# Keep container running
tail -f /dev/null
