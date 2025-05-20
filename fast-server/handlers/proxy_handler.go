package handlers

import (
	"crypto/tls"
	"fast/config"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/net/websocket"
	"io"
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

// isWebSocketRequest checks if the request is a WebSocket upgrade request
func isWebSocketRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

// handleWebSocketProxy handles proxying of WebSocket connections
func handleWebSocketProxy(c echo.Context, location *config.Location) error {
	proxyConfig := location.Proxy
	targetScheme := proxyConfig.Protocol
	if targetScheme == "" {
		targetScheme = "http"
	}

	// For WebSockets, if the target is https, we need to use wss instead
	wsScheme := "ws"
	if targetScheme == "https" {
		wsScheme = "wss"
	}

	// Build the target URL, preserving the path
	targetURL := fmt.Sprintf("%s://%s:%d%s",
		wsScheme,
		proxyConfig.Host,
		proxyConfig.Port,
		c.Request().URL.Path)

	if c.Request().URL.RawQuery != "" {
		targetURL += "?" + c.Request().URL.RawQuery
	}

	c.Logger().Infof("Proxying WebSocket connection to: %s", targetURL)

	// Determine the origin scheme based on the incoming request
	originScheme := "http"
	if c.Request().TLS != nil {
		originScheme = "https"
	}

	// Create a custom websocket config for the target connection
	targetConfig := websocket.Config{
		Location:  mustParseURL(targetURL),
		Origin:    mustParseURL(originScheme + "://" + c.Request().Host),
		Version:   websocket.ProtocolVersionHybi13,
		TlsConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Copy headers from the client request
	if targetConfig.Header == nil {
		targetConfig.Header = make(http.Header)
	}

	for k, v := range c.Request().Header {
		targetConfig.Header[k] = v
	}

	// Add or override proxy headers
	originalHost := c.Request().Host
	targetConfig.Header.Set("X-Forwarded-Host", originalHost)
	targetConfig.Header.Set("X-Real-IP", c.RealIP())
	targetConfig.Header.Set("X-Forwarded-For", c.RealIP())

	sourceScheme := "http"
	if c.Request().TLS != nil {
		sourceScheme = "https"
	}
	targetConfig.Header.Set("X-Forwarded-Proto", sourceScheme)
	targetConfig.Header.Set("X-Original-URI", c.Request().URL.Path)

	// Create the WebSocket handler
	websocket.Handler(func(clientConn *websocket.Conn) {
		defer clientConn.Close()

		// Connect to the backend service
		targetConn, err := websocket.DialConfig(&targetConfig)
		if err != nil {
			c.Logger().Errorf("Failed to connect to backend WebSocket: %v", err)
			return
		}
		defer targetConn.Close()

		c.Logger().Info("WebSocket connections established, beginning proxy")

		// Create a channel to monitor when the connections close
		errChan := make(chan error, 2)

		// Forward client messages to the target
		go func() {
			for {
				var message []byte
				err := websocket.Message.Receive(clientConn, &message)
				if err != nil {
					if err != io.EOF {
						c.Logger().Errorf("Error reading from client: %v", err)
					}
					errChan <- err
					return
				}

				err = websocket.Message.Send(targetConn, message)
				if err != nil {
					c.Logger().Errorf("Error writing to target: %v", err)
					errChan <- err
					return
				}
			}
		}()

		// Forward target messages to the client
		go func() {
			for {
				var message []byte
				err := websocket.Message.Receive(targetConn, &message)
				if err != nil {
					if err != io.EOF {
						c.Logger().Errorf("Error reading from target: %v", err)
					}
					errChan <- err
					return
				}

				err = websocket.Message.Send(clientConn, message)
				if err != nil {
					c.Logger().Errorf("Error writing to client: %v", err)
					errChan <- err
					return
				}
			}
		}()

		// Wait for either connection to close
		<-errChan
		c.Logger().Info("WebSocket proxy connection closed")
	}).ServeHTTP(c.Response(), c.Request())

	return nil
}

// Helper function to parse URLs and handle errors
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse URL %s: %v", rawURL, err))
	}
	return u
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

	// Check if this is a WebSocket request and handle it separately
	if isWebSocketRequest(c.Request()) {
		c.Logger().Info("Detected WebSocket request, handling with WebSocket proxy")
		return handleWebSocketProxy(c, location)
	}

	// Use location's proxy config for normal HTTP requests
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
