#!/bin/bash

# Build script for the web client
# This script is called during the Go build process

set -e

echo "Building web client..."

# Directory containing this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_DIR="$SCRIPT_DIR/client"

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "Node.js is required to build the web client"
    exit 1
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "npm is required to build the web client"
    exit 1
fi

# Navigate to the client directory
cd "$CLIENT_DIR"

# Install dependencies
echo "Installing dependencies..."
npm ci

# Build the client
echo "Building client..."
npm run build

echo "Web client built successfully!"