# Advanced Astro File Server

A high-performance, feature-rich file server specifically optimized for serving Astro builds with enhanced debugging, logging, and header support.

## Features

- **Astro-Optimized**: Special handling for Astro's folder-based output structure with nested index.html files
- **HTTP/2 Support**: Improved performance with multiplexing and header compression
- **Advanced Compression**: Both Brotli and Gzip compression for smaller file transfers
- **Intelligent Caching**: Content-hash detection, ETags, and optimized cache control headers
- **Performance Metrics**: Built-in metrics endpoint for monitoring
- **Smart Asset Preloading**: Automatic detection and preloading of critical resources
- **Memory Management**: Configurable cache size with smart eviction policy
- **Enhanced Directory Listings**: Beautiful, responsive directory listings in debug mode
- **Logging**: Structured logging with rotation and retention policies
- **Production-Ready**: Graceful shutdown, security headers, and more

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

## Command-Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | 8080 | Port to listen on |
| `--dir` | ./dist | Directory to serve files from |
| `--cache` | 3600 | Cache TTL in seconds (0 disables cache) |
| `--gzip` | true | Enable gzip compression |
| `--brotli` | true | Enable Brotli compression |
| `--log` | fileserver.log | Log file path (empty for stdout) |
| `--debug` | false | Enable debug mode |
| `--cert` | "" | SSL certificate file path |
| `--key` | "" | SSL key file path |
| `--spa` | true | Enable SPA mode (serve index.html for 404s) |
| `--astro` | true | Enable special handling for Astro's output structure |
| `--index` | index.html | Default index file name |
| `--http2` | true | Enable HTTP/2 support |
| `--preload` | true | Enable preloading of critical assets |
| `--asset-prefix` | _astro | Prefix for static assets |
| `--max-cache-size` | 100 | Maximum cache size in MB |
| `--metrics` | true | Enable performance metrics endpoint |
| `--log-max-size` | 10 | Maximum size of log files in MB |
| `--log-max-backups` | 3 | Maximum number of log file backups |
| `--log-max-age` | 28 | Maximum age of log file backups in days |
| `--log-format` | json | Log format (json or console) |

## Usage Examples

### Basic Usage

```bash
./fileserver --dir ./dist --port 3000
```

### Production Mode

```bash
./fileserver --dir ./dist --cache 86400 --max-cache-size 500 --log /var/log/fileserver.log
```

### Development Mode

```bash
./fileserver --dir ./dist --debug --log-format console --log ""
```

## Performance Optimization

The server implements several performance optimizations:

1. **Content-Hash Detection**: Automatically detects Astro's content-hashed assets and applies optimal caching
2. **Compression**: Uses Brotli (with fallback to gzip) for more efficient compression
3. **HTTP/2**: Modern protocol with multiplexing for faster loading
4. **Preloading**: Automatic detection and preloading of critical assets
5. **Memory Management**: Smart cache eviction based on access patterns
6. **Optimized Headers**: Properly configured cache control and ETag handling

## Metrics and Monitoring

Access the `/metrics` endpoint to view server performance statistics:

- Cache hit rates
- Response times
- Top requested routes
- Compression savings
- Memory usage

## Integration with Astro

This file server is designed to work seamlessly with Astro builds. It automatically detects and optimizes for Astro's output directory structure where each route has its own directory with an index.html file.

```
dist/
├── _astro/
│   ├── client.a1b2c3d4.js
│   └── styles.e5f6g7h8.css
├── index.html
├── login/
│   └── index.html
├── profile/
│   └── index.html
└── reset-password/
    └── index.html
```

## License

MIT