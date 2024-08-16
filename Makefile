# Build Fast Server
BINARY_NAME=fast_server
BUILD_DIR=builds
INSTALL_DIR=/usr/local/bin
CONFIG_DIR=/etc/fast
LOG_DIR=/var/log/fast
WWW_DIR=/var/www/fast

.PHONY: all linux darwin windows clean install uninstall

all: linux darwin windows

linux:
	@echo "Building $(BINARY_NAME) for Linux..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux main.go

darwin:
	@echo "Building $(BINARY_NAME) for macOS..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin main.go

windows:
	@echo "Building $(BINARY_NAME) for Windows..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows.exe main.go

clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)

install: linux
	@echo "Installing $(BINARY_NAME)..."
	@sudo mkdir -p $(INSTALL_DIR) $(CONFIG_DIR) $(CONFIG_DIR)/ssl $(LOG_DIR) $(WWW_DIR)
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME)-linux $(INSTALL_DIR)/$(BINARY_NAME)
	@sudo cp config.yaml $(CONFIG_DIR)/config.yaml
	@sudo cp -R public/* $(WWW_DIR)/
	@echo "Creating systemd service..."
	@sudo tee /etc/systemd/system/fast.service > /dev/null <<EOF
[Unit]
Description=FAST - HTTP Static Site Server
After=network.target

[Service]
ExecStart=$(INSTALL_DIR)/$(BINARY_NAME)
Restart=always
User=root
Group=root
Environment=PATH=/usr/bin:/usr/local/bin
WorkingDirectory=$(WWW_DIR)

[Install]
WantedBy=multi-user.target
EOF
	@sudo systemctl daemon-reload
	@sudo systemctl enable fast.service
	@echo "FAST server installed. Start with: sudo systemctl start fast"

uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	@sudo systemctl stop fast || true
	@sudo systemctl disable fast || true
	@sudo rm -f /etc/systemd/system/fast.service
	@sudo rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@sudo rm -rf $(CONFIG_DIR)
	@sudo rm -rf $(LOG_DIR)
	@sudo rm -rf $(WWW_DIR)
	@sudo systemctl daemon-reload
	@echo "FAST server uninstalled"