#!/bin/bash
set -e

# Load environment variables
if [ ! -f .env ]; then
    echo "Creating .env file from example..."
    cp .env.example .env
    echo "Please edit the .env file with your configuration and run this script again."
    exit 1
fi

# Source environment variables
source .env

# Create necessary directories
mkdir -p nginx/conf.d nginx/letsencrypt logs/nginx

# Generate a random password if not set
if [ "$JWT_SECRET" = "generate_a_secure_jwt_secret" ]; then
    echo "Generating JWT secret..."
    sed -i "s/JWT_SECRET=.*/JWT_SECRET=$(openssl rand -hex 32)/" .env
fi

if [ "$TURN_SECRET" = "generate_a_secure_turn_secret" ]; then
    echo "Generating TURN secret..."
    sed -i "s/TURN_SECRET=.*/TURN_SECRET=$(openssl rand -hex 32)/" .env
fi

# Build and start containers
echo "Building and starting containers..."
docker-compose -f docker-compose.prod.yml up -d --build

echo "Waiting for services to start..."
sleep 10

# Set up SSL with Let's Encrypt
echo "Setting up SSL certificate..."
docker-compose -f docker-compose.prod.yml run --rm certbot certonly \
    --webroot --webroot-path /var/www/certbot \
    --email admin@$DOMAIN \
    --agree-tos \
    --no-eff-email \
    -d $DOMAIN \
    -d www.$DOMAIN

echo "Reloading Nginx configuration..."
docker-compose -f docker-compose.prod.yml exec nginx nginx -s reload

echo "Deployment complete!"
echo "Access your application at: https://$DOMAIN"

# Show container status
echo -e "\nContainer status:"
docker-compose -f docker-compose.prod.yml ps
