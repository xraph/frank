#!/bin/bash
# Start ngrok tunnel for Frank Authentication Server

PORT=$(grep -E "^PORT=" .env | cut -d= -f2)
PORT=${PORT:-8000}  # Default to 8000 if not found

DOMAIN=$(grep -E "^NGROK_DOMAIN=" .env | cut -d= -f2)

echo "🚇 Starting ngrok tunnel to port $PORT..."

if [ -n "$DOMAIN" ]; then
    echo "Using custom domain: $DOMAIN"
    ngrok http --domain="$DOMAIN" "$PORT"
else
    ngrok http --subdomain=test "$PORT"
fi
