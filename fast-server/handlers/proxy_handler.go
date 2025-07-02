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

// handleWebSocketProxy handles proxying of WebSocket connections using gorilla/websocket
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

	// Build the target URL
	targetURL := fmt.Sprintf("%s://%s:%d%s",
		wsScheme,
		proxyConfig.Host,
		proxyConfig.Port,
		c.Request().URL.Path)

	if c.Request().URL.RawQuery != "" {
		targetURL += "?" + c.Request().URL.RawQuery
	}

	c.Logger().Infof("Proxying WebSocket connection to: %s", targetURL)

	// Create a dialer for connecting to the backend
	dialer := &websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: proxyConfig.InsecureSkipVerify,
		},
		HandshakeTimeout: 10 * time.Second,
	}

	// Create new headers for the backend request
	requestHeader := make(http.Header)

	// Copy all non-WebSocket headers
	for k, v := range c.Request().Header {
		k = strings.ToLower(k)
		if k != "upgrade" && k != "connection" && k != "sec-websocket-key" &&
			k != "sec-websocket-version" && k != "sec-websocket-extensions" {
			for _, val := range v {
				requestHeader.Add(k, val)
			}
		}
	}

	// Copy WebSocket protocol if specified
	if proto := c.Request().Header.Get("Sec-WebSocket-Protocol"); proto != "" {
		// Use the Subprotocols field
		for _, p := range strings.Split(proto, ",") {
			dialer.Subprotocols = append(dialer.Subprotocols, strings.TrimSpace(p))
		}
	}

	// CRITICAL: Set the Host header to the ORIGINAL host, not the backend host
	// This preserves the domain information that the backend needs for routing
	originalHost := c.Request().Host
	requestHeader.Set("Host", originalHost) // THIS IS THE KEY FIX

	// Add proxy headers
	requestHeader.Set("X-Forwarded-Host", originalHost)
	requestHeader.Set("X-Real-IP", c.RealIP())
	requestHeader.Set("X-Forwarded-For", c.RealIP())

	sourceScheme := "http"
	if c.Request().TLS != nil {
		sourceScheme = "https"
	}
	requestHeader.Set("X-Forwarded-Proto", sourceScheme)
	requestHeader.Set("X-Original-URI", c.Request().URL.Path)

	// Keep or set Origin header
	if origin := c.Request().Header.Get("Origin"); origin != "" {
		requestHeader.Set("Origin", origin)
	} else {
		requestHeader.Set("Origin", sourceScheme+"://"+originalHost)
	}

	// Upgrader for the client connection
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins
		},
	}

	// Upgrade the client connection
	clientConn, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		c.Logger().Errorf("Failed to upgrade client connection: %v", err)
		return echo.ErrInternalServerError
	}
	defer clientConn.Close()

	// Connect to the backend
	c.Logger().Infof("Connecting to backend with host header: %s", requestHeader.Get("Host"))
	backendConn, resp, err := dialer.Dial(targetURL, requestHeader)
	if err != nil {
		c.Logger().Errorf("Failed to connect to backend WebSocket: %v", err)
		if resp != nil {
			errorMsg := fmt.Sprintf("Backend error: %d %s", resp.StatusCode, resp.Status)
			clientConn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseInternalServerErr, errorMsg))
		}
		return nil
	}
	defer backendConn.Close()

	c.Logger().Info("WebSocket connections established, beginning proxy")

	// Create channels for the proxy
	clientDone := make(chan struct{})
	backendDone := make(chan struct{})

	// Copy messages from client to backend
	go func() {
		defer close(clientDone)
		for {
			messageType, message, err := clientConn.ReadMessage()
			if err != nil {
				c.Logger().Debugf("Client closed connection: %v", err)
				break
			}

			err = backendConn.WriteMessage(messageType, message)
			if err != nil {
				c.Logger().Errorf("Error writing to backend: %v", err)
				break
			}
		}
		// Signal the backend to close with a normal closure
		backendConn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	}()

	// Copy messages from backend to client
	go func() {
		defer close(backendDone)
		for {
			messageType, message, err := backendConn.ReadMessage()
			if err != nil {
				c.Logger().Debugf("Backend closed connection: %v", err)
				break
			}

			err = clientConn.WriteMessage(messageType, message)
			if err != nil {
				c.Logger().Errorf("Error writing to client: %v", err)
				break
			}
		}
		// Signal the client to close with a normal closure
		clientConn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	}()

	// Wait for either connection to finish
	select {
	case <-clientDone:
		c.Logger().Debug("Client connection closed first")
	case <-backendDone:
		c.Logger().Debug("Backend connection closed first")
	}

	c.Logger().Info("WebSocket proxy connection terminated")
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
			InsecureSkipVerify: proxyConfig.InsecureSkipVerify, // Using the config setting
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
