# FAST - HTTP Static Site Server and Reverse Proxy

FAST (File Access Speedy Transfer) is a lightweight,
high-performance web server designed for serving static content and acting as a reverse proxy.
It prioritizes speed and efficiency, making it ideal for quickly delivering static assets and proxying requests to
backend services.

## Features

- Multi-domain support
- SSL/TLS encryption
- HTTP to HTTPS redirection
- Domain-specific public directories
- Reverse proxy support
- Easy configuration via YAML
- Systemd service integration
- Minimal configuration required, allowing for quick setup and deployment
- Optimized for serving static files and proxying requests
- Optimized for serving file directories with resume on disconnect support for downloads
- High concurrency, able to handle multiple simultaneous connections efficiently
- Low memory footprint, making it suitable for various hosting environments
- Built-in caching mechanisms to further enhance performance
- Support for common web technologies like HTTP/2, SSL/TLS, and compression

## Prerequisites

- Go 1.16 or higher
- Make
- Systemd (for service installation)
- Root access (for installation)

## Installation

1. Clone the repository:

    ```bash
   git clone https://github.com/pollystack/fast.git
   cd fast-server
    ```
2. Modify the `config.yaml.example` file to suit your needs and rename it to `config.yaml`.

3. Build and install the server:

    ```bash
   sudo make install
    ```

   This will:
   - Build the server for Linux
   - Copy the binary to `/usr/local/bin/fast_server`
   - Copy the configuration to `/etc/fast/config.yaml`
   - Set up a systemd service

4. Start the server:

    ```bash
   sudo systemctl start fast
    ```

## Configuration

The server is configured via the `config.yaml` file. Here's an example configuration:

```yaml
server:
   port: 443
   http_port: 80  # for HTTP to HTTPS redirect

domains:

   - name: static.example.com
     type: static
     public_dir: /var/www/fast/static.example.com
     ssl:
        cert_file: /etc/fast/ssl/static.example.com/fullchain.pem
        key_file: /etc/fast/ssl/static.example.com/privkey.pem

   - name: files.example.com
     type: file_directory
     public_dir: /var/www/fast/files.example.com
     ssl:
        cert_file: /etc/fast/ssl/files.example.com/fullchain.pem
        key_file: /etc/fast/ssl/files.example.com/privkey.pem

   - name: api.example.com
     type: proxy
     proxy:
        host: 192.168.1.100
        port: 8000
     ssl:
        cert_file: /etc/fast/ssl/api.example.com/fullchain.pem
        key_file: /etc/fast/ssl/api.example.com/privkey.pem

global_ssl:
   cert_file: /etc/fast/ssl/global/fullchain.pem
   key_file: /etc/fast/ssl/global/privkey.pem

log:
   file: /var/log/fast/server.log
   level: info  # Options: debug, info, warn, error

settings:
   read_timeout: 5s
   write_timeout: 10s
   graceful_shutdown_timeout: 30s

is_development: false
```


## Usage

### Starting the Server

The server is set up as a systemd service during installation. You can manage it using standard systemd commands:

- Start: `sudo systemctl start fast`
- Stop: `sudo systemctl stop fast`
- Restart: `sudo systemctl restart fast`
- Check status: `sudo systemctl status fast`

### Logs
Logs are stored in /var/log/fast/server.log by default. You can view them using:

```bash
sudo tail -f /var/log/fast/server.log
```

## Usage Docker

### Prerequisites
- Docker
- Make

### Build
Build the Docker image:
```bash
make docker-build
```

### Run
Start the FAST server in a Docker container:
```bash
make docker-run
```

### Stop
Stop and remove the running Docker container:
```bash
make docker-stop
```

### Logs
View logs from the Docker container:

```bash
docker logs fast-server-container
```

## Development

### Prerequisites

- Go 1.16 or higher
- gops tool (optional, for improved debug detection)

### Generate Test Certs

```bash
openssl req -x509 -newkey rsa:4096 -keyout fast-server/test/ssl/domain1.lan/privkey.pem -out fast-server/test/ssl/domain1.lan/fullchain.pem -days 365 -nodes -subj "/CN=domain1.lan"
openssl req -x509 -newkey rsa:4096 -keyout fast-server/test/ssl/domain2.lan/privkey.pem -out fast-server/test/ssl/domain2.lan/fullchain.pem -days 365 -nodes -subj "/CN=domain2.lan"
openssl req -x509 -newkey rsa:4096 -keyout fast-server/test/ssl/global/privkey.pem -out fast-server/test/ssl/global/fullchain.pem -days 365 -nodes -subj "/CN=localhost"

```

To install gops:
```bash
go install github.com/google/gops@latest

```

### Project Structure

```azure
fast-server
├── config
│   └── config.go
├── go.mod
├── go.sum
├── handlers
│   ├── file_directory_handler.go
│   ├── handlers.go
│   ├── proxy_handler.go
│   └── static_handler.go
├── main.go
├── server
│   └── server.go
├── templates
│   └── file_directory.html
└── test
    ├── config.yaml
    └── public
```

### Building

- Build for all platforms: `make all`
- Build for Linux: `make linux`
- Build for macOS: `make darwin`
- Build for Windows: `make windows`

### Cleaning

To remove all built binaries:
```bash
make clean
```

## Uninstallation
To uninstall the server:
```bash
sudo make uninstall
```
This will stop the service, remove the binary, configuration, and created directories.

## Acronym

FAST stands for:

- **F**ile
- **A**ccess
- **S**peedy
- **T**ransfer

Emphasizing its core functionality of rapidly serving static files.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

If you encounter any problems or have any questions, please open an issue on the GitHub repository.
