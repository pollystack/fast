package handlers

import (
	"bytes"
	"crypto/tls"
	"fast/config"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	loadBalancerCounter uint32
	activeConnections   sync.Map
)

const (
	LoadBalanceMethodRoundRobin = "round_robin"
	LoadBalanceMethodLeastConn  = "least_conn"
)

func getNextHost(proxyConfig config.ProxyConfig) string {
	// If only single host is specified, return it
	if len(proxyConfig.Hosts) == 0 {
		return proxyConfig.Host
	}

	// Choose load balancing method
	switch proxyConfig.LoadBalanceMethod {
	case LoadBalanceMethodLeastConn:
		return getLeastConnHost(proxyConfig.Hosts)
	case LoadBalanceMethodRoundRobin:
		return getRoundRobinHost(proxyConfig.Hosts)
	default:
		// If no method specified or unknown, default to round_robin
		return getRoundRobinHost(proxyConfig.Hosts)
	}
}

func getRoundRobinHost(hosts []string) string {
	next := atomic.AddUint32(&loadBalancerCounter, 1)
	return hosts[next%uint32(len(hosts))]
}

func getLeastConnHost(hosts []string) string {
	var selectedHost string
	minConns := int64(math.MaxInt64)

	for _, host := range hosts {
		// Initialize with 0 if not exists
		connsValue, _ := activeConnections.LoadOrStore(host, int64(0))
		currentConns := connsValue.(int64)
		if currentConns < minConns {
			minConns = currentConns
			selectedHost = host
		}
	}

	return selectedHost
}

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

	c.Logger().Debugf("Matched location path: %s", location.Path)

	// Use location's proxy config
	proxyConfig := location.Proxy

	// Get next host using load balancing
	selectedHost := getNextHost(proxyConfig)

	// Increment active connections for the selected host if using least_conn
	if proxyConfig.LoadBalanceMethod == LoadBalanceMethodLeastConn {
		connsValue, _ := activeConnections.LoadOrStore(selectedHost, int64(0))
		currentConns := connsValue.(int64)
		activeConnections.Store(selectedHost, currentConns+1)
		defer func() {
			connsValue, _ := activeConnections.Load(selectedHost)
			currentConns := connsValue.(int64)
			activeConnections.Store(selectedHost, currentConns-1)
		}()
		c.Logger().Debugf("Active connections for host %s: %d", selectedHost, currentConns+1)
	}

	targetScheme := proxyConfig.Protocol
	if targetScheme == "" {
		targetScheme = "http"
	}

	target, err := url.Parse(fmt.Sprintf("%s://%s:%d", targetScheme, selectedHost, proxyConfig.Port))
	if err != nil {
		c.Logger().Errorf("Error parsing proxy URL: %v", err)
		return echo.ErrInternalServerError
	}

	originalHost := c.Request().Host

	// Set up the rewrite rules
	var rewriteMap map[string]string
	if location.Path == "/" {
		rewriteMap = map[string]string{
			"/*": "/$1",
		}
	} else {
		rewriteMap = map[string]string{
			location.Path + "/*": location.Path + "/$1",
		}
	}

	c.Logger().Debugf("Using rewrite map: %v", rewriteMap)

	// More detailed logging for load balancing
	c.Logger().Infof("[LoadBalancer] %s request: %s → %s (host: %s, method: %s, scheme: %s)",
		proxyConfig.LoadBalanceMethod,
		originalHost+requestPath,
		target.String(),
		selectedHost,
		c.Request().Method,
		targetScheme,
	)

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: proxyConfig.InsecureSkipVerify,
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
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DisableCompression:    false,
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
			// Read and log the response body
			body, err := io.ReadAll(res.Body)
			if err != nil {
				c.Logger().Errorf("[LoadBalancer] Failed to read response body: %v", err)
				return err
			}
			err = res.Body.Close()
			if err != nil {
				c.Logger().Errorf("[LoadBalancer] Failed to read response body: %v", err)
				return err
			}
			// Create new ReadCloser for the body
			res.Body = io.NopCloser(bytes.NewBuffer(body))

			c.Logger().Infof("[LoadBalancer] Response from %s: %d %s, Content-Type: %s, Body: %s",
				selectedHost,
				res.StatusCode,
				http.StatusText(res.StatusCode),
				res.Header.Get("Content-Type"),
				string(body),
			)
			return nil
		},
	})

	// Set proxy headers with more detailed tracking
	c.Request().Header.Set("X-Forwarded-Host", originalHost)
	c.Request().Header.Set("X-Real-IP", c.RealIP())
	c.Request().Header.Set("X-Forwarded-For", c.RealIP())
	c.Request().Header.Set("X-Forwarded-Proto", sourceScheme)
	c.Request().Header.Set("X-Original-URI", requestPath)
	c.Request().Header.Set("X-Load-Balanced-Host", selectedHost)
	c.Request().Header.Set("X-Load-Balance-Method", proxyConfig.LoadBalanceMethod)
	c.Request().Host = originalHost

	return proxyMiddleware(func(c echo.Context) error {
		return nil
	})(c)
}
