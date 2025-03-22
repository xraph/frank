# Robust Go File Server for Astro

A high-performance, feature-rich file server specifically optimized for serving Astro builds with enhanced debugging, logging, and header support.

## Features

- **Optimized for Astro builds**: Proper MIME type handling for all Astro-related file types
- **High Performance**: File caching, ETags support, and pre-compressed content delivery
- **Advanced Logging**: Structured logging with Zap, configurable rotation and retention policies
- **SPA Support**: Option to serve index.html for client-side routing in Single Page Applications
- **Security Features**: Protection against directory traversal attacks and proper header handling
- **HTTPS Support**: Optional TLS configuration for secure connections
- **CORS Support**: Configurable cross-origin resource sharing
- **Debug Mode**: Directory listings and verbose logging when needed
- **Docker Support**: Ready to deploy with the included Dockerfile
- **Graceful Shutdown**: Properly handles termination signals

## Installation

### Using Go

```bash
# Clone the repository
git clone https://github.com/yourusername/astro-fileserver.git
cd astro-fileserver

# Install dependencies
go mod download

# Build
go build -o fileserver

# Run
./fileserver --dir /path/to/astro/dist --port 8080
```

### Using Docker

```bash
# Build the Docker image
docker build -t astro-fileserver .

# Run the container
docker run -p 8080:8080 -v /path/to/astro/dist:/app/dist astro-fileserver
```

## Command-Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | 8080 | Port to listen on |
| `--dir` | ./dist | Directory to serve files from |
| `--cache` | 3600 | Cache TTL in seconds (0 disables cache) |
| `--gzip` | true | Enable gzip compression |
| `--cors` | true | Enable CORS |
| `--log` | fileserver.log | Log file path (empty for stdout) |
| `--debug` | false | Enable debug mode |
| `--cert` | "" | SSL certificate file path |
| `--key` | "" | SSL key file path |
| `--spa` | true | Enable SPA mode (serve index.html for 404s) |
| `--index` | index.html | Default index file name |
| `--log-max-size` | 10 | Maximum size of log files in MB |
| `--log-max-backups` | 3 | Maximum number of log file backups |
| `--log-max-age` | 28 | Maximum age of log file backups in days |
| `--log-format` | json | Log format (json or console) |

## Usage Examples

### Basic Usage

```bash
./fileserver --dir ./dist --port 3000
```

### With HTTPS

```bash
./fileserver --dir ./dist --port 443 --cert ./cert.pem --key ./key.pem
```

### Debug Mode with Console Logging

```bash
./fileserver --dir ./dist --debug --log ""
```

### Production Mode with Optimized Settings

```bash
./fileserver --dir ./dist --cache 86400 --gzip --spa --log /var/log/fileserver.log --log-max-size 100
```

## Integration with Astro

This file server is designed to work seamlessly with Astro builds. After building your Astro project with `npm run build`, you can serve the generated files from the `dist` directory:

```bash
./fileserver --dir /path/to/astro/project/dist
```

## Advanced Configuration

### HTTPS Setup

To enable HTTPS, generate a certificate and key:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout key.pem -out cert.pem
```

Then run the server with the certificate and key:

```bash
./fileserver --cert ./cert.pem --key ./key.pem
```

### Docker Compose Example

```yaml
version: '3'
services:
  fileserver:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./dist:/app/dist
      - ./logs:/logs
    command: --dir /app/dist --log /logs/fileserver.log
```

## Performance Optimization

The server implements several performance optimizations:

1. **File Caching**: Files are cached in memory to reduce disk I/O
2. **ETags**: Proper ETag handling for client-side caching
3. **Pre-compression**: Files are pre-compressed when possible
4. **Conditional GET**: Supports If-None-Match headers for 304 responses

## License

MIT