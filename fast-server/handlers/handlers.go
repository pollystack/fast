package handlers

import (
	"fast/config"
	"github.com/labstack/echo/v4"
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
			c.Logger().Infof("Incoming request for host: %s", host)

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
				c.Logger().Warnf("No matching domain found for host: %s", host)
				return echo.ErrNotFound
			}

			c.Logger().Infof("Matched domain: %s", matchedName)
			c.Set("domain", matchedDomain)
			return next(c)
		}
	})

	// Root handler
	e.GET("/", handleRequest)

	// Catch-all handler
	e.GET("/*", handleRequest)
}

func handleRequest(c echo.Context) error {
	domain := c.Get("domain").(config.Domain)
	switch domain.Type {
	case "proxy":
		return HandleProxy(c, domain)
	case "file_directory":
		return HandleFileDirectory(c, domain)
	default:
		return ServeIndexOrFile(c, domain.PublicDir, c.Request().URL.Path)
	}
}
