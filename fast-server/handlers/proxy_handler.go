package handlers

import (
	"crypto/tls"
	"fast/config"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
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

	// Copy ALL headers first (this is important for double-proxy setups)
	for k, v := range c.Request().Header {
		// Skip headers that will be handled specially or by gorilla/websocket
		lowerK := strings.ToLower(k)
		if lowerK == "upgrade" ||
			lowerK == "connection" ||
			lowerK == "sec-websocket-key" ||
			lowerK == "sec-websocket-version" ||
			lowerK == "sec-websocket-extensions" ||
			lowerK == "sec-websocket-protocol" {
			continue
		}
		requestHeader[k] = v
	}

	// Handle WebSocket-specific headers
	// gorilla/websocket handles most of these automatically, but we need to handle subprotocols
	if proto := c.Request().Header.Get("Sec-WebSocket-Protocol"); proto != "" {
		dialer.Subprotocols = strings.Split(proto, ",")
		for i := range dialer.Subprotocols {
			dialer.Subprotocols[i] = strings.TrimSpace(dialer.Subprotocols[i])
		}
	}

	// Note: Do NOT manually set Sec-WebSocket-Extensions as gorilla/websocket handles this
	// The dialer will negotiate extensions automatically

	// CRITICAL: For double-proxy setup, we need to handle the Host header carefully
	// Check if we already have X-Forwarded-Host from the first proxy
	originalHost := c.Request().Header.Get("X-Forwarded-Host")
	if originalHost == "" {
		// If not, use the current request's host
		originalHost = c.Request().Host
	}

	// Set the Host header to the ORIGINAL host (from the first request)
	requestHeader.Set("Host", originalHost)

	// Add/Update proxy headers for the chain
	requestHeader.Set("X-Forwarded-Host", originalHost)

	// Handle X-Forwarded-For to maintain the chain
	forwardedFor := c.Request().Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		// Append our IP to the existing chain
		requestHeader.Set("X-Forwarded-For", forwardedFor+", "+c.RealIP())
	} else {
		requestHeader.Set("X-Forwarded-For", c.RealIP())
	}

	requestHeader.Set("X-Real-IP", c.RealIP())

	// Handle X-Forwarded-Proto - preserve from first proxy if available
	forwardedProto := c.Request().Header.Get("X-Forwarded-Proto")
	if forwardedProto == "" {
		if c.Request().TLS != nil {
			forwardedProto = "https"
		} else {
			forwardedProto = "http"
		}
	}
	requestHeader.Set("X-Forwarded-Proto", forwardedProto)

	requestHeader.Set("X-Original-URI", c.Request().URL.Path)

	// Handle Origin header - preserve from original request
	if origin := c.Request().Header.Get("Origin"); origin != "" {
		requestHeader.Set("Origin", origin)
	} else {
		// Construct origin from the original host
		requestHeader.Set("Origin", forwardedProto+"://"+originalHost)
	}

	// Add debug logging for double-proxy scenario
	c.Logger().Infof("WebSocket proxy chain debug:")
	c.Logger().Infof("  Original Host: %s", originalHost)
	c.Logger().Infof("  Target URL: %s", targetURL)
	c.Logger().Infof("  X-Forwarded-Host: %s", requestHeader.Get("X-Forwarded-Host"))
	c.Logger().Infof("  X-Forwarded-For: %s", requestHeader.Get("X-Forwarded-For"))
	c.Logger().Infof("  Origin: %s", requestHeader.Get("Origin"))

	// Upgrader for the client connection
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins in proxy scenario
		},
		// Enable compression if the client supports it
		EnableCompression: true,
	}

	// Upgrade the client connection
	clientConn, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		c.Logger().Errorf("Failed to upgrade client connection: %v", err)
		return echo.ErrInternalServerError
	}
	defer clientConn.Close()

	// Connect to the backend
	c.Logger().Infof("Connecting to backend with headers: %v", requestHeader)
	backendConn, resp, err := dialer.Dial(targetURL, requestHeader)
	if err != nil {
		c.Logger().Errorf("Failed to connect to backend WebSocket: %v", err)
		if resp != nil {
			c.Logger().Errorf("Backend response status: %d %s", resp.StatusCode, resp.Status)
			// Try to read error body
			if resp.Body != nil {
				bodyBytes, _ := io.ReadAll(resp.Body)
				c.Logger().Errorf("Backend error body: %s", string(bodyBytes))
			}
		}
		errorMsg := fmt.Sprintf("Backend error: %v", err)
		if resp != nil {
			errorMsg = fmt.Sprintf("Backend error: %d %s", resp.StatusCode, resp.Status)
		}
		clientConn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, errorMsg))
		return nil
	}
	defer backendConn.Close()

	c.Logger().Info("WebSocket connections established, beginning proxy")

	// Create channels for the proxy
	clientDone := make(chan struct{})
	backendDone := make(chan struct{})

	// Error channel to capture any errors
	errChan := make(chan error, 2)

	// Copy messages from client to backend
	go func() {
		defer close(clientDone)
		for {
			messageType, message, err := clientConn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					c.Logger().Errorf("Client read error: %v", err)
					errChan <- err
				} else {
					c.Logger().Debugf("Client closed connection normally: %v", err)
				}
				break
			}

			if err := backendConn.WriteMessage(messageType, message); err != nil {
				c.Logger().Errorf("Error writing to backend: %v", err)
				errChan <- err
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
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					c.Logger().Errorf("Backend read error: %v", err)
					errChan <- err
				} else {
					c.Logger().Debugf("Backend closed connection normally: %v", err)
				}
				break
			}

			if err := clientConn.WriteMessage(messageType, message); err != nil {
				c.Logger().Errorf("Error writing to client: %v", err)
				errChan <- err
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
	case err := <-errChan:
		c.Logger().Errorf("WebSocket proxy error: %v", err)
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
