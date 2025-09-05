package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fast/config"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/labstack/echo/v4"
	"gopkg.in/yaml.v2"
)

type AdminKeyPair struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
	CreatedAt  string `json:"created_at"`
}

type DomainAuthUpdate struct {
	DomainName     string   `json:"domain_name"`
	Enabled        bool     `json:"enabled"`
	PublicKey      string   `json:"public_key"`
	RequireBrowser bool     `json:"require_browser"`
	TokenLifetime  int      `json:"token_lifetime"`
	AllowedHosts   []string `json:"allowed_hosts"`
}

// HandleAdminPanel serves the main admin interface
func HandleAdminPanel(c echo.Context) error {
	// Check if request is from localhost or has admin token
	if !isAdminAuthorized(c) {
		return echo.NewHTTPError(403, "Admin access denied")
	}

	// Load current configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		c.Logger().Errorf("Failed to load config: %v", err)
		return echo.NewHTTPError(500, "Failed to load configuration")
	}

	// Get stored keys if any
	storedKeys := loadStoredKeys()

	return c.Render(http.StatusOK, "admin.html", map[string]interface{}{
		"Config":     cfg,
		"Domains":    cfg.Domains,
		"StoredKeys": storedKeys,
	})
}

// HandleGenerateKeys generates a new EC key pair
func HandleGenerateKeys(c echo.Context) error {
	if !isAdminAuthorized(c) {
		return echo.NewHTTPError(403, "Admin access denied")
	}

	// Generate ECDSA key pair with P-256 curve
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		c.Logger().Errorf("Failed to generate keys: %v", err)
		return echo.NewHTTPError(500, "Failed to generate keys")
	}

	// Encode private key to PEM
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return echo.NewHTTPError(500, "Failed to marshal private key")
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encode public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return echo.NewHTTPError(500, "Failed to marshal public key")
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	keyPair := AdminKeyPair{
		PublicKey:  string(publicKeyPEM),
		PrivateKey: string(privateKeyPEM),
		CreatedAt:  "Just now",
	}

	// Save keys to file
	saveKeyPair(keyPair)

	return c.JSON(http.StatusOK, keyPair)
}

// HandleUpdateDomainAuth updates authentication settings for a domain
func HandleUpdateDomainAuth(c echo.Context) error {
	if !isAdminAuthorized(c) {
		return echo.NewHTTPError(403, "Admin access denied")
	}

	var update DomainAuthUpdate
	if err := c.Bind(&update); err != nil {
		return echo.NewHTTPError(400, "Invalid request")
	}

	// Load current config
	cfg, err := config.LoadConfig()
	if err != nil {
		return echo.NewHTTPError(500, "Failed to load configuration")
	}

	// Find and update the domain
	found := false
	for i, domain := range cfg.Domains {
		if domain.Name == update.DomainName {
			// Update auth settings
			cfg.Domains[i].Auth = config.AuthConfig{
				Enabled:        update.Enabled,
				Type:           "ec",
				PublicKey:      update.PublicKey,
				RequireBrowser: update.RequireBrowser,
				TokenLifetime:  update.TokenLifetime,
				AllowedHosts:   update.AllowedHosts,
			}
			found = true
			break
		}
	}

	if !found {
		return echo.NewHTTPError(404, "Domain not found")
	}

	// Save updated config
	if err := saveConfig(cfg); err != nil {
		c.Logger().Errorf("Failed to save config: %v", err)
		return echo.NewHTTPError(500, "Failed to save configuration")
	}

	return c.JSON(http.StatusOK, map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Updated auth settings for %s", update.DomainName),
	})
}

// HandleAddDomain adds a new domain to the configuration
func HandleAddDomain(c echo.Context) error {
	if !isAdminAuthorized(c) {
		return echo.NewHTTPError(403, "Admin access denied")
	}

	var newDomain config.Domain
	if err := c.Bind(&newDomain); err != nil {
		return echo.NewHTTPError(400, "Invalid request")
	}

	// Load current config
	cfg, err := config.LoadConfig()
	if err != nil {
		return echo.NewHTTPError(500, "Failed to load configuration")
	}

	// Check if domain already exists
	for _, domain := range cfg.Domains {
		if domain.Name == newDomain.Name {
			return echo.NewHTTPError(400, "Domain already exists")
		}
	}

	// Add the new domain
	cfg.Domains = append(cfg.Domains, newDomain)

	// Save updated config
	if err := saveConfig(cfg); err != nil {
		c.Logger().Errorf("Failed to save config: %v", err)
		return echo.NewHTTPError(500, "Failed to save configuration")
	}

	return c.JSON(http.StatusOK, map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Added domain %s", newDomain.Name),
	})
}

// HandleDeleteDomain removes a domain from configuration
func HandleDeleteDomain(c echo.Context) error {
	if !isAdminAuthorized(c) {
		return echo.NewHTTPError(403, "Admin access denied")
	}

	domainName := c.Param("domain")
	if domainName == "" {
		return echo.NewHTTPError(400, "Domain name required")
	}

	// Load current config
	cfg, err := config.LoadConfig()
	if err != nil {
		return echo.NewHTTPError(500, "Failed to load configuration")
	}

	// Find and remove the domain
	newDomains := []config.Domain{}
	found := false
	for _, domain := range cfg.Domains {
		if domain.Name != domainName {
			newDomains = append(newDomains, domain)
		} else {
			found = true
		}
	}

	if !found {
		return echo.NewHTTPError(404, "Domain not found")
	}

	cfg.Domains = newDomains

	// Save updated config
	if err := saveConfig(cfg); err != nil {
		c.Logger().Errorf("Failed to save config: %v", err)
		return echo.NewHTTPError(500, "Failed to save configuration")
	}

	return c.JSON(http.StatusOK, map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Deleted domain %s", domainName),
	})
}

// HandleTestAuthentication tests EC authentication for a domain
func HandleTestAuthentication(c echo.Context) error {
	if !isAdminAuthorized(c) {
		return echo.NewHTTPError(403, "Admin access denied")
	}

	domainName := c.QueryParam("domain")
	token := c.QueryParam("token")

	if domainName == "" || token == "" {
		return echo.NewHTTPError(400, "Domain and token required")
	}

	// Load config to get domain auth settings
	cfg, err := config.LoadConfig()
	if err != nil {
		return echo.NewHTTPError(500, "Failed to load configuration")
	}

	// Find domain
	var targetDomain *config.Domain
	for _, domain := range cfg.Domains {
		if domain.Name == domainName {
			targetDomain = &domain
			break
		}
	}

	if targetDomain == nil {
		return echo.NewHTTPError(404, "Domain not found")
	}

	if !targetDomain.Auth.Enabled {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"status":  "info",
			"message": "Authentication not enabled for this domain",
		})
	}

	// Verify token
	authConfig := ECAuthConfig{
		PublicKey:     targetDomain.Auth.PublicKey,
		AllowedHosts:  targetDomain.Auth.AllowedHosts,
		TokenLifetime: targetDomain.Auth.TokenLifetime,
	}

	valid, err := VerifyECDSASignature(authConfig.PublicKey, []byte(token), "test-signature")
	if err != nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"status":  "error",
			"message": fmt.Sprintf("Verification failed: %v", err),
		})
	}

	if valid {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"status":  "success",
			"message": "Authentication successful",
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":  "error",
		"message": "Invalid token",
	})
}

// Helper functions

func isAdminAuthorized(c echo.Context) bool {
	// Check if request is from localhost
	remoteAddr := c.Request().RemoteAddr
	if strings.HasPrefix(remoteAddr, "127.0.0.1:") ||
		strings.HasPrefix(remoteAddr, "[::1]:") ||
		strings.HasPrefix(remoteAddr, "localhost:") {
		return true
	}

	// Check for admin token in header
	adminToken := c.Request().Header.Get("X-Admin-Token")
	expectedToken := os.Getenv("FAST_ADMIN_TOKEN")
	if expectedToken != "" && adminToken == expectedToken {
		return true
	}

	return false
}

func loadStoredKeys() []AdminKeyPair {
	// Load keys from storage directory
	keysDir := "/etc/fast/keys"
	if _, err := os.Stat(keysDir); os.IsNotExist(err) {
		os.MkdirAll(keysDir, 0700)
		return []AdminKeyPair{}
	}

	files, err := ioutil.ReadDir(keysDir)
	if err != nil {
		return []AdminKeyPair{}
	}

	var keys []AdminKeyPair
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".json") {
			data, err := ioutil.ReadFile(filepath.Join(keysDir, file.Name()))
			if err != nil {
				continue
			}
			var keyPair AdminKeyPair
			if err := json.Unmarshal(data, &keyPair); err != nil {
				continue
			}
			keys = append(keys, keyPair)
		}
	}

	return keys
}

func saveKeyPair(keyPair AdminKeyPair) error {
	keysDir := "/etc/fast/keys"
	os.MkdirAll(keysDir, 0700)

	filename := fmt.Sprintf("keypair_%d.json", len(loadStoredKeys())+1)
	data, err := json.MarshalIndent(keyPair, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filepath.Join(keysDir, filename), data, 0600)
}

func saveConfig(cfg *config.Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	configPath := config.ProductionConfigPath
	if isLaunchedByDebugger() {
		configPath = "test/config.yaml"
	}

	return ioutil.WriteFile(configPath, data, 0644)
}

func isLaunchedByDebugger() bool {
	// Reuse the function from config.go
	return strings.Contains(os.Args[0], "debugger") || strings.Contains(os.Args[0], "___go_build_")
}
