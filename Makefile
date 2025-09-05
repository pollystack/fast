# Build Fast Server
BINARY_NAME=fast_server
BUILD_DIR=builds
INSTALL_DIR=/usr/local/bin
CONFIG_DIR=/etc/fast
LOG_DIR=/var/log/fast
WWW_DIR=/var/www/fast
CODE_DIR=fast-server
KEYS_DIR=/etc/fast/keys
SSL_DIR=/etc/fast/ssl

.PHONY: all linux darwin windows clean install uninstall docker-compose-up docker-compose-down docker-compose-build docker-compose-logs init-dev test-build

all: linux darwin windows

linux:
	@echo "Building $(BINARY_NAME) for Linux..."
	@cd $(CODE_DIR) && go get -v && \
	mkdir -p $(BUILD_DIR) && \
	GOOS=linux go build -o $(BUILD_DIR)/$(BINARY_NAME) main.go

darwin:
	@echo "Building $(BINARY_NAME) for macOS..."
	@cd $(CODE_DIR) && go get -v && \
	mkdir -p $(BUILD_DIR) && \
	GOOS=darwin go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin main.go

windows:
	@echo "Building $(BINARY_NAME) for Windows..."
	@cd $(CODE_DIR) && go get -v && \
	mkdir -p $(BUILD_DIR) && \
	GOOS=windows go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows.exe main.go

clean:
	@echo "Cleaning..."
	@rm -rf $(CODE_DIR)/$(BUILD_DIR)
	@echo "Build artifacts cleaned"

install: linux
	@echo "Installing $(BINARY_NAME)..."
	@echo "Creating directories..."
	@sudo mkdir -p $(INSTALL_DIR)
	@sudo mkdir -p $(CONFIG_DIR)
	@sudo mkdir -p $(CONFIG_DIR)/ssl
	@sudo mkdir -p $(CONFIG_DIR)/ssl/global
	@sudo mkdir -p $(KEYS_DIR)
	@sudo mkdir -p $(LOG_DIR)
	@sudo mkdir -p $(WWW_DIR)
	@sudo mkdir -p $(WWW_DIR)/default

	@echo "Setting permissions..."
	@sudo chmod 700 $(KEYS_DIR)
	@sudo chmod 755 $(CONFIG_DIR)
	@sudo chmod 755 $(LOG_DIR)
	@sudo chmod 755 $(WWW_DIR)

	@echo "Copying binary..."
	@sudo cp $(CODE_DIR)/$(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	@sudo chmod +x $(INSTALL_DIR)/$(BINARY_NAME)

	@echo "Installing configuration..."
	@if [ ! -f $(CONFIG_DIR)/config.yaml ]; then \
		sudo cp config.yaml.example $(CONFIG_DIR)/config.yaml; \
		echo "Installed default config to $(CONFIG_DIR)/config.yaml"; \
	else \
		echo "Config already exists at $(CONFIG_DIR)/config.yaml - skipping"; \
	fi

	@echo "Creating default index.html..."
	@if [ ! -f $(WWW_DIR)/default/index.html ]; then \
		sudo bash -c 'echo "<!DOCTYPE html><html><head><title>FAST Server</title></head><body><h1>FAST Server Running</h1><p>EC Authentication Ready</p></body></html>" > $(WWW_DIR)/default/index.html'; \
	fi

	@echo "Creating systemd service..."
	@sudo bash -c 'printf "[Unit]\nDescription=FAST - HTTP Static Site Server with EC Auth\nAfter=network.target\n\n[Service]\nType=simple\nRestart=always\nRestartSec=5s\nExecStart=$(INSTALL_DIR)/$(BINARY_NAME)\nUser=root\nGroup=root\nEnvironment=PATH=/usr/bin:/usr/local/bin\nEnvironment=FAST_CONFIG=$(CONFIG_DIR)/config.yaml\nWorkingDirectory=$(WWW_DIR)\nStandardOutput=append:$(LOG_DIR)/fast.log\nStandardError=append:$(LOG_DIR)/fast-error.log\n\n[Install]\nWantedBy=multi-user.target\n" > /lib/systemd/system/fast.service'

	@echo "Reloading systemd..."
	@sudo systemctl daemon-reload

	@echo "Enabling service..."
	@sudo systemctl enable fast.service

	@echo ""
	@echo "============================================"
	@echo "FAST server installed successfully!"
	@echo "============================================"
	@echo ""
	@echo "Directories created:"
	@echo "  Config:     $(CONFIG_DIR)"
	@echo "  Keys:       $(KEYS_DIR)"
	@echo "  SSL:        $(SSL_DIR)"
	@echo "  Logs:       $(LOG_DIR)"
	@echo "  Web Root:   $(WWW_DIR)"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Edit config:  sudo nano $(CONFIG_DIR)/config.yaml"
	@echo "  2. Start server: sudo systemctl start fast"
	@echo "  3. Check status: sudo systemctl status fast"
	@echo "  4. View logs:    sudo journalctl -u fast -f"
	@echo "  5. Admin panel:  https://localhost/admin"
	@echo ""
	@echo "For EC authentication setup:"
	@echo "  - Generate keys at: https://localhost/admin"
	@echo "  - Keys stored in:   $(KEYS_DIR)"
	@echo "============================================"

uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	@sudo systemctl stop fast || true
	@sudo systemctl disable fast || true
	@sudo rm -f /lib/systemd/system/fast.service
	@sudo rm -f $(INSTALL_DIR)/$(BINARY_NAME)

	@echo "Do you want to remove configuration and data? [y/N]"
	@read -r response; \
	if [ "$$response" = "y" ] || [ "$$response" = "Y" ]; then \
		echo "Removing configuration and data..."; \
		sudo rm -rf $(CONFIG_DIR); \
		sudo rm -rf $(LOG_DIR); \
		sudo rm -rf $(WWW_DIR); \
	else \
		echo "Keeping configuration and data"; \
	fi

	@sudo systemctl daemon-reload
	@echo "FAST server uninstalled"

# Development commands
test-build:
	@echo "Running test build..."
	@cd $(CODE_DIR) && go test ./...
	@cd $(CODE_DIR) && go build -o test-binary main.go
	@rm -f $(CODE_DIR)/test-binary
	@echo "Test build successful"

# Docker Compose commands
docker-compose-build:
	@echo "Building with Docker Compose..."
	docker-compose build

docker-compose-up:
	@echo "Starting with Docker Compose..."
	docker-compose up -d

docker-compose-down:
	@echo "Stopping with Docker Compose..."
	docker-compose down

docker-compose-logs:
	@echo "Viewing Docker Compose logs..."
	docker-compose logs -f

# Initialize development environment
init-dev:
	@echo "Initializing development environment..."

	@echo "Creating directory structure..."
	@mkdir -p $(CODE_DIR)/test/keys
	@mkdir -p $(CODE_DIR)/test/ssl/domain1.lan
	@mkdir -p $(CODE_DIR)/test/ssl/domain2.lan
	@mkdir -p $(CODE_DIR)/test/ssl/global
	@mkdir -p $(CODE_DIR)/test/www/domain1.lan
	@mkdir -p $(CODE_DIR)/test/www/domain2.lan
	@mkdir -p $(CODE_DIR)/test/www/protected
	@mkdir -p $(CODE_DIR)/test/logs

	@echo "Copying example configurations..."
	@if [ ! -f $(CODE_DIR)/test/config.yaml ]; then \
		cp config.yaml.example $(CODE_DIR)/test/config.yaml; \
		echo "Created test config at $(CODE_DIR)/test/config.yaml"; \
	fi

	@if [ ! -f .env ]; then \
		echo "# Environment variables for development" > .env; \
		echo "FAST_ADMIN_TOKEN=dev-admin-token" >> .env; \
		echo "DEBUG=true" >> .env; \
		echo "Created .env file"; \
	fi

	@echo "Generating test certificates..."
	@openssl req -x509 -newkey rsa:4096 -keyout $(CODE_DIR)/test/ssl/domain1.lan/privkey.pem -out $(CODE_DIR)/test/ssl/domain1.lan/fullchain.pem -days 365 -nodes -subj "/CN=domain1.lan" 2>/dev/null
	@openssl req -x509 -newkey rsa:4096 -keyout $(CODE_DIR)/test/ssl/domain2.lan/privkey.pem -out $(CODE_DIR)/test/ssl/domain2.lan/fullchain.pem -days 365 -nodes -subj "/CN=domain2.lan" 2>/dev/null
	@openssl req -x509 -newkey rsa:4096 -keyout $(CODE_DIR)/test/ssl/global/privkey.pem -out $(CODE_DIR)/test/ssl/global/fullchain.pem -days 365 -nodes -subj "/CN=localhost" 2>/dev/null

	@echo "Creating test HTML files..."
	@echo '<!DOCTYPE html><html><head><title>Domain 1</title></head><body><h1>Domain 1 Test Site</h1></body></html>' > $(CODE_DIR)/test/www/domain1.lan/index.html
	@echo '<!DOCTYPE html><html><head><title>Domain 2</title></head><body><h1>Domain 2 Test Site</h1></body></html>' > $(CODE_DIR)/test/www/domain2.lan/index.html
	@echo '<!DOCTYPE html><html><head><title>Protected</title></head><body><h1>Protected Site - EC Auth Required</h1></body></html>' > $(CODE_DIR)/test/www/protected/index.html

	@echo ""
	@echo "============================================"
	@echo "Development environment initialized!"
	@echo "============================================"
	@echo ""
	@echo "Test domains created:"
	@echo "  - domain1.lan"
	@echo "  - domain2.lan"
	@echo ""
	@echo "Add to /etc/hosts:"
	@echo "  127.0.0.1 domain1.lan domain2.lan"
	@echo ""
	@echo "Run development server:"
	@echo "  cd $(CODE_DIR) && go run main.go"
	@echo ""
	@echo "Access admin panel:"
	@echo "  https://localhost/admin"
	@echo "============================================"

# Generate EC keys for testing
generate-test-keys:
	@echo "Generating EC test keys..."
	@cd $(CODE_DIR) && go run -mod=mod - <<'EOF' \
	package main; \
	import ( \
		"crypto/ecdsa" \
		"crypto/elliptic" \
		"crypto/rand" \
		"crypto/x509" \
		"encoding/pem" \
		"fmt" \
		"os" \
	); \
	func main() { \
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); \
		privateKeyBytes, _ := x509.MarshalECPrivateKey(privateKey); \
		privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes}); \
		publicKeyBytes, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey); \
		publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}); \
		os.WriteFile("test/keys/test-private.pem", privateKeyPEM, 0600); \
		os.WriteFile("test/keys/test-public.pem", publicKeyPEM, 0644); \
		fmt.Println("Test EC keys generated in test/keys/"); \
		fmt.Printf("Public Key:\n%s\n", publicKeyPEM); \
	} \
	EOF

# Run development server
run-dev:
	@echo "Starting development server..."
	@cd $(CODE_DIR) && DEBUG=true go run main.go

# Check installation
check-install:
	@echo "Checking FAST installation..."
	@echo ""
	@if [ -f $(INSTALL_DIR)/$(BINARY_NAME) ]; then \
		echo "✓ Binary installed at $(INSTALL_DIR)/$(BINARY_NAME)"; \
	else \
		echo "✗ Binary not found"; \
	fi
	@if [ -f $(CONFIG_DIR)/config.yaml ]; then \
		echo "✓ Config exists at $(CONFIG_DIR)/config.yaml"; \
	else \
		echo "✗ Config not found"; \
	fi
	@if [ -d $(KEYS_DIR) ]; then \
		echo "✓ Keys directory exists at $(KEYS_DIR)"; \
	else \
		echo "✗ Keys directory not found"; \
	fi
	@if systemctl is-enabled fast >/dev/null 2>&1; then \
		echo "✓ Service is enabled"; \
	else \
		echo "✗ Service not enabled"; \
	fi
	@if systemctl is-active fast >/dev/null 2>&1; then \
		echo "✓ Service is running"; \
	else \
		echo "✗ Service not running"; \
	fi

# View logs
logs:
	@sudo journalctl -u fast -f

# Restart service
restart:
	@echo "Restarting FAST service..."
	@sudo systemctl restart fast
	@echo "Service restarted"

# Help
help:
	@echo "FAST Server Makefile"
	@echo ""
	@echo "Build targets:"
	@echo "  make linux        - Build for Linux"
	@echo "  make darwin       - Build for macOS"
	@echo "  make windows      - Build for Windows"
	@echo "  make all          - Build for all platforms"
	@echo ""
	@echo "Installation:"
	@echo "  make install      - Install FAST server (Linux)"
	@echo "  make uninstall    - Uninstall FAST server"
	@echo "  make check-install - Check installation status"
	@echo ""
	@echo "Development:"
	@echo "  make init-dev     - Initialize development environment"
	@echo "  make test-build   - Run tests and verify build"
	@echo "  make generate-test-keys - Generate test EC keys"
	@echo "  make run-dev      - Run development server"
	@echo ""
	@echo "Service management:"
	@echo "  make restart      - Restart FAST service"
	@echo "  make logs         - View service logs"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-compose-build - Build Docker image"
	@echo "  make docker-compose-up    - Start with Docker"
	@echo "  make docker-compose-down  - Stop Docker containers"
	@echo "  make docker-compose-logs  - View Docker logs"
	@echo ""
	@echo "Other:"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make help         - Show this help"

.DEFAULT_GOAL := help