# Build Fast Server
BINARY_NAME=fast_server
BUILD_DIR=builds
INSTALL_DIR=/usr/local/bin
CONFIG_DIR=/etc/fast
LOG_DIR=/var/log/fast
WWW_DIR=/var/www/fast
DOCKER_IMAGE_NAME=fast-server
CODE_DIR=fast-server
DOCKER_CONTAINER_NAME=fast-server-container

.PHONY: all linux darwin windows clean install uninstall docker-build docker-run docker-stop

all: linux darwin windows

linux:
	@echo "Building $(BINARY_NAME) for Linux..."
	@cd $(CODE_DIR) && go get -d -v && \
	mkdir -p $(BUILD_DIR) && \
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME) main.go

darwin:
	@echo "Building $(BINARY_NAME) for macOS..."
	@cd $(CODE_DIR) && go get -d -v && \
	mkdir -p $(BUILD_DIR) && \
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin main.go

windows:
	@echo "Building $(BINARY_NAME) for Windows..."
	@cd $(CODE_DIR) && go get -d -v && \
	mkdir -p $(BUILD_DIR) && \
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows.exe main.go
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)

install: linux
	@echo "Installing $(BINARY_NAME)..."
	@sudo mkdir -p $(INSTALL_DIR) $(CONFIG_DIR) $(CONFIG_DIR)/ssl $(LOG_DIR) $(WWW_DIR)
	@sudo cp $(CODE_DIR)/$(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	@sudo cp config.yaml.example $(CONFIG_DIR)/config.yaml
	@echo "Creating systemd service..."
	@sudo printf "[Unit]\nDescription=FAST - HTTP Static Site Server\nAfter=network.target\n\n[Service]\nType=simple\nRestart=always\nRestartSec=5s\nExecStart=$(INSTALL_DIR)/$(BINARY_NAME)\nUser=root\nGroup=root\nEnvironment=PATH=/usr/bin:/usr/local/bin\nWorkingDirectory=$(WWW_DIR)\n\n[Install]\nWantedBy=multi-user.target\n" > /lib/systemd/system/fast.service
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

docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE_NAME) .

docker-run:
	@echo "Running Docker container..."
	docker run -d \
		-p 80:80 \
		-p 443:443 \
		-v $(WWW_DIR):/var/www/fast \
		-v $(CONFIG_DIR)/ssl:/etc/fast/ssl \
		-v $(LOG_DIR):/var/log/fast \
		-v $(CONFIG_DIR)/config.yaml:/etc/fast/config.yaml \
		--name $(DOCKER_CONTAINER_NAME) \
		$(DOCKER_IMAGE_NAME)

docker-stop:
	@echo "Stopping Docker container..."
	docker stop $(DOCKER_CONTAINER_NAME)
	docker rm $(DOCKER_CONTAINER_NAME)