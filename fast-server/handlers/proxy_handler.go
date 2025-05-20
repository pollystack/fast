package handlers

import (
	"crypto/tls"
	"fast/config"
	"fmt"
	"github.com/gorilla/websocket"
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

// isWebSocketRequest checks if the request is a WebSocket upgrade request
func isWebSocketRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
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

	// Check if this is a WebSocket request
	if isWebSocketRequest(c.Request()) {
		c.Logger().Info("Detected WebSocket request")
		return handleWebSocket(c, location)
	}

	// Use location's proxy config for regular HTTP requests
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
			InsecureSkipVerify: proxyConfig.InsecureSkipVerify, // IMPORTANT: Using the setting from config
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

// Simple WebSocket handler for testing
func handleWebSocket(c echo.Context, location *config.Location) error {
	// Initialize the upgrader with lax security restrictions
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins for testing
		},
	}

	// Get proxy config
	proxyConfig := location.Proxy
	targetScheme := proxyConfig.Protocol
	if targetScheme == "" {
		targetScheme = "http"
	}

	// Translate http/https to ws/wss
	wsScheme := "ws"
	if targetScheme == "https" {
		wsScheme = "wss"
	}

	// Build target URL
	targetURL := fmt.Sprintf("%s://%s:%d%s",
		wsScheme,
		proxyConfig.Host,
		proxyConfig.Port,
		c.Request().URL.Path)

	if c.Request().URL.RawQuery != "" {
		targetURL += "?" + c.Request().URL.RawQuery
	}

	c.Logger().Infof("Proxying WebSocket connection to: %s", targetURL)

	// Upgrade the client connection
	clientConn, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		c.Logger().Errorf("Failed to upgrade client connection: %v", err)
		return err
	}
	defer clientConn.Close()

	// Prepare headers for backend connection
	header := http.Header{}
	for k, v := range c.Request().Header {
		if !strings.EqualFold(k, "Upgrade") &&
			!strings.EqualFold(k, "Connection") &&
			!strings.EqualFold(k, "Sec-Websocket-Key") &&
			!strings.EqualFold(k, "Sec-Websocket-Version") &&
			!strings.EqualFold(k, "Sec-Websocket-Extensions") {
			header[k] = v
		}
	}

	// Add proxy headers
	header.Set("X-Forwarded-Host", c.Request().Host)
	header.Set("X-Real-IP", c.RealIP())
	header.Set("X-Forwarded-For", c.RealIP())

	sourceScheme := "http"
	if c.Request().TLS != nil {
		sourceScheme = "https"
	}
	header.Set("X-Forwarded-Proto", sourceScheme)
	header.Set("X-Original-URI", c.Request().URL.Path)

	// Connect to backend - USE THE PROXY CONFIG SETTING
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: proxyConfig.InsecureSkipVerify, // IMPORTANT: Using config setting
		},
		HandshakeTimeout: 10 * time.Second,
	}

	backendConn, resp, err := dialer.Dial(targetURL, header)
	if err != nil {
		c.Logger().Errorf("Failed to connect to backend: %v", err)
		// Send close message to client
		clientConn.WriteMessage(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseAbnormalClosure, "Failed to connect to backend"))
		return nil
	}
	defer backendConn.Close()

	// Handle backend response problems
	if resp != nil && resp.StatusCode >= 400 {
		c.Logger().Errorf("Backend responded with error: %d", resp.StatusCode)
		clientConn.WriteMessage(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseAbnormalClosure, fmt.Sprintf("Backend error: %d", resp.StatusCode)))
		return nil
	}

	c.Logger().Info("WebSocket proxying established")

	// Channels to signal when done
	doneCh := make(chan bool, 2)

	// Copy from client to backend
	go func() {
		defer func() {
			doneCh <- true
		}()

		for {
			// Read message from client
			msgType, msg, err := clientConn.ReadMessage()
			if err != nil {
				c.Logger().Debugf("Client read error: %v", err)
				break
			}

			// Write message to backend
			err = backendConn.WriteMessage(msgType, msg)
			if err != nil {
				c.Logger().Debugf("Backend write error: %v", err)
				break
			}
		}
	}()

	// Copy from backend to client
	go func() {
		defer func() {
			doneCh <- true
		}()

		for {
			// Read message from backend
			msgType, msg, err := backendConn.ReadMessage()
			if err != nil {
				c.Logger().Debugf("Backend read error: %v", err)
				break
			}

			// Write message to client
			err = clientConn.WriteMessage(msgType, msg)
			if err != nil {
				c.Logger().Debugf("Client write error: %v", err)
				break
			}
		}
	}()

	// Wait for either goroutine to finish
	<-doneCh

	c.Logger().Info("WebSocket proxy connection closed")

	// Try to close connections gracefully
	clientConn.WriteMessage(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	backendConn.WriteMessage(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))

	// Wait a bit to allow close messages to be sent
	time.Sleep(100 * time.Millisecond)

	return nil
}
