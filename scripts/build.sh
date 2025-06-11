#!/bin/bash

set -e

echo "🏗️  Building Frank Auth for production..."

# Colors
GREEN='\033[0;32m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[BUILD]${NC} $1"
}

# Clean previous builds
clean_build() {
    print_status "Cleaning previous builds..."
    rm -rf web/apps/dashboard/out
    rm -rf web/apps/dashboard/.next
    rm -rf dist
    mkdir -p dist
}

# Build frontend
build_frontend() {
    print_status "Building frontend applications..."

    cd web

    # Install dependencies
    pnpm install --frozen-lockfile

    # Build all apps
    pnpm build

    cd ..

    print_status "Frontend build completed ✅"
}

# Build backend
build_backend() {
    print_status "Building Go backend..."

    # Set build variables
    VERSION=$(git describe --tags --always --dirty)
    BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Build with embedded frontend
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -ldflags="-w -s -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}" \
        -o dist/frank-auth \
        cmd/frank/main.go

    print_status "Backend build completed ✅"
}

# Create deployment package
create_package() {
    print_status "Creating deployment package..."

    # Copy configuration files
    cp -r configs dist/
    cp -r migrations dist/
    cp -r templates dist/

    # Create deployment scripts
    cat > dist/deploy.sh << 'EOF'
#!/bin/bash
echo "Deploying Frank Auth..."
./frank-auth migrate up
./frank-auth server
EOF
    chmod +x dist/deploy.sh

    # Create systemd service file
    cat > dist/frank-auth.service << 'EOF'
[Unit]
Description=Frank Auth Service
After=network.target

[Service]
Type=simple
User=frank
WorkingDirectory=/opt/frank-auth
ExecStart=/opt/frank-auth/frank-auth server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    print_status "Deployment package created ✅"
}

# Main build process
main() {
    clean_build
    build_frontend
    build_backend
    create_package

    print_status "Build completed successfully! 🎉"
    print_status "Deployment files are in ./dist/"
}

main "$@"