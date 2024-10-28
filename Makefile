# Build Fast Server
BINARY_NAME=fast_server
BUILD_DIR=builds
INSTALL_DIR=/usr/local/bin
CONFIG_DIR=/etc/fast
LOG_DIR=/var/log/fast
WWW_DIR=/var/www/fast
CODE_DIR=fast-server

.PHONY: all linux darwin windows clean install uninstall docker-compose-up docker-compose-down docker-compose-build docker-compose-logs

all: linux darwin windows

linux:
	@echo "Building $(BINARY_NAME) for Linux..."
	@cd $(CODE_DIR) && go get -d -v && \
	mkdir -p $(BUILD_DIR) && \
	GOOS=linux go build -o $(BUILD_DIR)/$(BINARY_NAME) main.go

darwin:
	@echo "Building $(BINARY_NAME) for macOS..."
	@cd $(CODE_DIR) && go get -d -v && \
	mkdir -p $(BUILD_DIR) && \
	GOOS=darwin go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin main.go

windows:
	@echo "Building $(BINARY_NAME) for Windows..."
	@cd $(CODE_DIR) && go get -d -v && \
	mkdir -p $(BUILD_DIR) && \
	GOOS=windows go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows.exe main.go

clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)

install: linux
	@echo "Installing $(BINARY_NAME)..."
	@sudo mkdir -p $(INSTALL_DIR) $(CONFIG_DIR) $(CONFIG_DIR)/ssl $(LOG_DIR) $(WWW_DIR)
	@sudo cp $(CODE_DIR)/$(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	@sudo cp config.yaml.example $(CONFIG_DIR)/config.yaml
	@echo "Creating systemd service..."
	@sudo bash -c 'printf "[Unit]\nDescription=FAST - HTTP Static Site Server\nAfter=network.target\n\n[Service]\nType=simple\nRestart=always\nRestartSec=5s\nExecStart=$(INSTALL_DIR)/$(BINARY_NAME)\nUser=root\nGroup=root\nEnvironment=PATH=/usr/bin:/usr/local/bin\nWorkingDirectory=$(WWW_DIR)\n\n[Install]\nWantedBy=multi-user.target\n" > /lib/systemd/system/fast.service'
	@echo "FAST server installed. Start with:"
	@echo "-----------------------------------"
	@echo " $> sudo service fast start"
	@echo "-----------------------------------"
	@echo "Enabling Service"
	@sudo systemctl enable fast.service

uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	@sudo systemctl stop fast || true
	@sudo systemctl disable fast || true
	@sudo rm -f /lib/systemd/system/fast.service
	@sudo rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@sudo rm -rf $(CONFIG_DIR)
	@sudo rm -rf $(LOG_DIR)
	@sudo systemctl daemon-reload
	@echo "FAST server uninstalled"

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
	@cp config.yaml.example config.yaml
	@cp .env.example .env
	@mkdir -p ssl/domain1.lan ssl/domain2.lan ssl/global www logs
	@echo "Generating test certificates..."
	@openssl req -x509 -newkey rsa:4096 -keyout ssl/domain1.lan/privkey.pem -out ssl/domain1.lan/fullchain.pem -days 365 -nodes -subj "/CN=domain1.lan"
	@openssl req -x509 -newkey rsa:4096 -keyout ssl/domain2.lan/privkey.pem -out ssl/domain2.lan/fullchain.pem -days 365 -nodes -subj "/CN=domain2.lan"
	@openssl req -x509 -newkey rsa:4096 -keyout ssl/global/privkey.pem -out ssl/global/fullchain.pem -days 365 -nodes -subj "/CN=localhost"
