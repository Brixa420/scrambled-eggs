FROM coturn/coturn:latest

# Install certbot for Let's Encrypt
RUN apt-get update && apt-get install -y certbot

# Copy configuration
COPY coturn.conf /etc/coturn/turnserver.conf

# Create log directory
RUN mkdir -p /var/log/coturn && \
    touch /var/log/coturn/turnserver.log && \
    chown -R turnserver:turnserver /var/log/coturn

# Expose ports
EXPOSE 3478 3478/udp
EXPOSE 5349 5349/udp
EXPOSE 49152-65535/udp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD turnutils_uclient -t -n 10 -m 10 -y -w 10 -a -v -e 127.0.0.1 || exit 1

# Start script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
