package config

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

var ProductionConfigPath = "/etc/fast/config.yaml"

type Domain struct {
	Name      string `yaml:"name"`
	Type      string `yaml:"type"`
	PublicDir string `yaml:"public_dir"`
	Proxy     struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"proxy"`
	SSL struct {
		CertFile string `yaml:"cert_file"`
		KeyFile  string `yaml:"key_file"`
	} `yaml:"ssl"`
}

type Config struct {
	Server struct {
		Port     int `yaml:"port"`
		HTTPPort int `yaml:"http_port"`
	} `yaml:"server"`
	Domains   []Domain `yaml:"domains"`
	GlobalSSL struct {
		CertFile string `yaml:"cert_file"`
		KeyFile  string `yaml:"key_file"`
	} `yaml:"global_ssl"`
	Log struct {
		File  string `yaml:"file"`
		Level string `yaml:"level"`
	} `yaml:"log"`
	Settings struct {
		ReadTimeout             string `yaml:"read_timeout"`
		WriteTimeout            string `yaml:"write_timeout"`
		GracefulShutdownTimeout string `yaml:"graceful_shutdown_timeout"`
	} `yaml:"settings"`
	IsDevelopment bool `yaml:"is_development"`
}

func isLaunchedByDebugger() bool {
	// Check if gops is available
	_, err := exec.LookPath("gops")
	if err != nil {
		// If gops is not available, fall back to a simple check
		return strings.Contains(os.Args[0], "debugger") || strings.Contains(os.Args[0], "___go_build_")
	}

	// Use gops to check the parent process
	gopsOut, err := exec.Command("gops", strconv.Itoa(os.Getppid())).Output()
	if err != nil {
		log.Printf("Error running gops: %v", err)
		return false
	}

	gopsOutStr := string(gopsOut)

	switch runtime.GOOS {
	case "windows":
		return strings.Contains(gopsOutStr, "\\dlv.exe")
	case "darwin":
		return strings.Contains(gopsOutStr, "/dlv") ||
			strings.Contains(gopsOutStr, "/dlv-dap") ||
			strings.Contains(gopsOutStr, "debugserver")
	default: // linux and others
		return strings.Contains(gopsOutStr, "/dlv")
	}
}

func LoadConfig() (*Config, error) {
	var configPath string
	if isLaunchedByDebugger() {
		configPath = "fast-server/test/config.yaml" // Local path for development
		log.Println("Debug mode detected. Using local config.yaml")
	} else {
		configPath = ProductionConfigPath // Default production path
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	return &config, nil
}
