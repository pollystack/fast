package handlers

import (
	"crypto/tls"
	"fast/config"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

func getMatchingLocation(path string, locations []config.Location) *config.Location {
	// Sort locations by path length in descending order (longest first)
	sortedLocations := make([]config.Location, len(locations))
	copy(sortedLocations, locations)
	sort.Slice(sortedLocations, func(i, j int) bool {
		return len(sortedLocations[i].Path) > len(sortedLocations[j].Path)
	})

	// Find the first matching location
	for i, loc := range sortedLocations {
		if strings.HasPrefix(path, loc.Path) {
			return &sortedLocations[i]
		}
	}

	return nil
}

func HandleProxy(c echo.Context, domain config.Domain) error {
	requestPath := c.Request().URL.Path
	c.Logger().Infof("Original request path: %s", requestPath)

	// Get matching location
	location := getMatchingLocation(requestPath, domain.Locations)
	if location == nil {
		c.Logger().Errorf("No matching location found for path: %s", requestPath)
		return echo.ErrNotFound
	}

	c.Logger().Infof("Matched location path: %s", location.Path)

	// Use location's proxy config
	proxyConfig := location.Proxy
	targetScheme := proxyConfig.Protocol
	if targetScheme == "" {
		targetScheme = "http"
	}

	target, err := url.Parse(fmt.Sprintf("%s://%s:%d", targetScheme, proxyConfig.Host, proxyConfig.Port))
	if err != nil {
		c.Logger().Errorf("Error parsing proxy URL: %v", err)
		return echo.ErrInternalServerError
	}

	originalHost := c.Request().Host

	// Create rewrite map based on location path
	rewriteMap := make(map[string]string)
	if location.Path == "/" {
		rewriteMap["/*"] = "/$1"
	} else {
		rewriteMap[location.Path+"/*"] = location.Path + "/$1"
	}

	c.Logger().Infof("Using rewrite map: %v", rewriteMap)
	c.Logger().Infof("Proxying %s request from %s%s to %s%s",
		c.Request().Method, originalHost, requestPath, target.String(), requestPath)

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, // Always skip verification for proxied requests
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       0, // Changed from 90s for streaming
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 0, // Changed from 30s for streaming
		DisableCompression:    false,
		DisableKeepAlives:     false,     // Added for streaming
		ReadBufferSize:        64 * 1024, // Added for streaming (64KB)
		WriteBufferSize:       64 * 1024, // Added for streaming (64KB)
	}

	sourceScheme := "http"
	if c.Request().TLS != nil {
		sourceScheme = "https"
	}

	proxyMiddleware := middleware.ProxyWithConfig(middleware.ProxyConfig{
		Balancer: middleware.NewRoundRobinBalancer([]*middleware.ProxyTarget{
			{
				URL: target,
			},
		}),
		Rewrite:   rewriteMap,
		Transport: transport,
		ModifyResponse: func(res *http.Response) error {
			c.Logger().Infof("Proxy response status: %d for path: %s", res.StatusCode, requestPath)

			// Always treat as streaming
			res.Header.Del("Content-Length")          // Remove content length to allow streaming
			res.Header.Set("X-Accel-Buffering", "no") // Disable nginx buffering

			return nil
		},
	})

	// Set proxy headers
	c.Request().Header.Set("X-Forwarded-Host", originalHost)
	c.Request().Header.Set("X-Real-IP", c.RealIP())
	c.Request().Header.Set("X-Forwarded-For", c.RealIP())
	c.Request().Header.Set("X-Forwarded-Proto", sourceScheme)
	c.Request().Header.Set("X-Original-URI", requestPath)
	c.Request().Host = originalHost

	return proxyMiddleware(func(c echo.Context) error {
		return nil
	})(c)
}
