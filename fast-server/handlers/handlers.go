package handlers

import (
	"fast/config"
	"fmt"
	"github.com/labstack/echo/v4"
	"log"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func SetupDomainRoutes(e *echo.Echo, domains []config.Domain) {
	// Create a map for quick domain lookup
	domainMap := make(map[string]config.Domain)
	for _, domain := range domains {
		domainMap[domain.Name] = domain
	}

	// Single middleware to handle all domains
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			host := c.Request().Host
			if strings.Contains(host, ":") {
				host = strings.Split(host, ":")[0]
			}
			log.Printf("Incoming request for host: %s", host)

			var matchedDomain config.Domain
			var matchedName string
			for domainName, domain := range domainMap {
				if strings.HasSuffix(host, domainName) {
					if len(domainName) > len(matchedName) {
						matchedDomain = domain
						matchedName = domainName
					}
				}
			}

			if matchedName == "" {
				log.Printf("No matching domain found for host: %s", host)
				return echo.ErrNotFound
			}

			log.Printf("Matched domain: %s", matchedName)
			c.Set("domain", matchedDomain)
			return next(c)
		}
	})

	// Root handler
	e.GET("/*", func(c echo.Context) error {
		domain := c.Get("domain").(config.Domain)

		if domain.Type == "proxy" {
			return handleProxy(c, domain)
		}

		return serveIndexOrFile(c, domain.PublicDir, c.Request().URL.Path)
	})

}

func handleProxy(c echo.Context, domain config.Domain) error {
	target, err := url.Parse(fmt.Sprintf("http://%s:%d", domain.Proxy.Host, domain.Proxy.Port))
	if err != nil {
		log.Printf("Error parsing proxy URL: %v", err)
		return echo.ErrInternalServerError
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Update the headers to allow for SSL redirection
	req := c.Request()
	req.URL.Host = target.Host
	req.URL.Scheme = target.Scheme
	req.Header.Set("X-Forwarded-Host", req.Host)
	req.Header.Set("X-Forwarded-Proto", "https")

	proxy.ServeHTTP(c.Response(), req)
	return nil
}

func serveIndexOrFile(c echo.Context, publicDir, requestPath string) error {
	fullPath := filepath.Join(publicDir, filepath.Clean(requestPath))

	// Prevent directory traversal
	if !strings.HasPrefix(fullPath, publicDir) {
		log.Printf("Attempted directory traversal detected: %s", fullPath)
		return echo.ErrNotFound
	}

	if stat, err := os.Stat(fullPath); err == nil && !stat.IsDir() {
		log.Printf("Serving file: %s", fullPath)
		return c.File(fullPath)
	}

	// If file doesn't exist or is a directory, serve the root index.html
	indexPath := filepath.Join(publicDir, "index.html")
	log.Printf("Serving index.html: %s", indexPath)
	return c.File(indexPath)
}
