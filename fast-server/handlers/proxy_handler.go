package handlers

import (
	"bufio"
	"crypto/tls"
	"fast/config"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"net"
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

// Custom response writer that ensures no buffering for SSE
type unbufferedResponseWriter struct {
	http.ResponseWriter
	Flusher http.Flusher
}

func (u *unbufferedResponseWriter) Write(b []byte) (int, error) {
	n, err := u.ResponseWriter.Write(b)
	if err == nil {
		u.Flusher.Flush()
	}
	return n, err
}

func (u *unbufferedResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := u.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not support Hijack")
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
	locationProxyConfig := location.Proxy
	targetScheme := locationProxyConfig.Protocol
	if targetScheme == "" {
		targetScheme = "http"
	}

	target, err := url.Parse(fmt.Sprintf("%s://%s:%d", targetScheme, locationProxyConfig.Host, locationProxyConfig.Port))
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

	// Enhanced SSE detection
	isSSE := false
	acceptHeader := c.Request().Header.Get("Accept")
	contentTypeHeader := c.Request().Header.Get("Content-Type")

	// Check for SSE indicators in headers, URL path, and query parameters
	if acceptHeader == "text/event-stream" ||
		strings.Contains(requestPath, "/events") ||
		strings.Contains(requestPath, "/sse") ||
		strings.Contains(requestPath, "/stream") ||
		strings.Contains(c.QueryParam("type"), "stream") ||
		strings.Contains(contentTypeHeader, "text/event-stream") {
		isSSE = true
		c.Logger().Infof("Detected potential SSE request, optimizing proxy settings")
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: locationProxyConfig.InsecureSkipVerify,
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
		IdleConnTimeout:       0, // No timeout for streaming connections
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 0,     // No timeout for streaming responses
		DisableCompression:    isSSE, // Disable compression for SSE
		DisableKeepAlives:     false,
		ReadBufferSize:        64 * 1024, // 64KB
		WriteBufferSize:       64 * 1024, // 64KB
	}

	sourceScheme := "http"
	if c.Request().TLS != nil {
		sourceScheme = "https"
	}

	// Set proxy headers
	c.Request().Header.Set("X-Forwarded-Host", originalHost)
	c.Request().Header.Set("X-Real-IP", c.RealIP())
	c.Request().Header.Set("X-Forwarded-For", c.RealIP())
	c.Request().Header.Set("X-Forwarded-Proto", sourceScheme)
	c.Request().Header.Set("X-Original-URI", requestPath)
	c.Request().Host = originalHost

	// If request appears to be for SSE, ensure proper client headers
	if isSSE {
		// Use unbuffered response writer
		if flusher, ok := c.Response().Writer.(http.Flusher); ok {
			c.Response().Writer = &unbufferedResponseWriter{
				ResponseWriter: c.Response().Writer,
				Flusher:        flusher,
			}
			c.Logger().Info("Using unbuffered response writer for streaming")
		} else {
			c.Logger().Warn("Response writer doesn't support flushing, streaming may not work properly")
		}

		// Set appropriate headers
		c.Response().Header().Set("Content-Type", "text/event-stream")
		c.Response().Header().Set("Cache-Control", "no-cache")
		c.Response().Header().Set("Connection", "keep-alive")
		c.Response().Header().Set("X-Accel-Buffering", "no") // Disable Nginx buffering
	}

	proxyMiddlewareConfig := middleware.ProxyConfig{
		Balancer: middleware.NewRoundRobinBalancer([]*middleware.ProxyTarget{
			{
				URL: target,
			},
		}),
		Rewrite:   rewriteMap,
		Transport: transport,
		ModifyResponse: func(res *http.Response) error {
			c.Logger().Infof("Proxy response status: %d for path: %s", res.StatusCode, requestPath)

			// If this is an SSE response, ensure proper headers are preserved
			if res.Header.Get("Content-Type") == "text/event-stream" || isSSE {
				c.Logger().Info("SSE response detected, ensuring proper headers")

				// Ensure these headers are preserved
				res.Header.Set("Cache-Control", "no-cache")
				res.Header.Set("Connection", "keep-alive")
				res.Header.Set("X-Accel-Buffering", "no") // Disable Nginx buffering

				// Remove any Content-Length header which would prevent streaming
				res.Header.Del("Content-Length")

				// Ensure chunked transfer encoding
				res.TransferEncoding = []string{"chunked"}
			}

			return nil
		},
	}

	proxyMiddleware := middleware.ProxyWithConfig(proxyMiddlewareConfig)
	return proxyMiddleware(func(c echo.Context) error {
		return nil
	})(c)
}
