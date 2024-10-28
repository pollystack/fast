package handlers

import (
	"crypto/tls"
	"fast/config"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"net/http"
	"net/url"
	"time"
)

func HandleProxy(c echo.Context, domain config.Domain) error {

	// Determine scheme based on request
	scheme := "http"
	if c.Request().TLS != nil {
		scheme = "https"
	}

	target, err := url.Parse(fmt.Sprintf("%s://%s:%d", scheme, domain.Proxy.Host, domain.Proxy.Port))
	if err != nil {
		c.Logger().Errorf("Error parsing proxy URL: %v", err)
		return echo.ErrInternalServerError
	}

	originalHost := c.Request().Host
	c.Logger().Infof("Proxying %s request from %s to %s",
		c.Request().Method, originalHost, target.String())

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, // Disabled for Proxy
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
		DisableCompression:    false,
	}

	proxyMiddleware := middleware.ProxyWithConfig(middleware.ProxyConfig{
		Balancer: middleware.NewRoundRobinBalancer([]*middleware.ProxyTarget{
			{
				URL: target,
			},
		}),
		Rewrite: map[string]string{
			"/*": "/$1",
		},
		Transport: transport,
	})

	// Set proxy headers before proxying the request
	c.Request().Header.Set("X-Forwarded-Host", originalHost)
	c.Request().Header.Set("X-Real-IP", c.RealIP())
	c.Request().Header.Set("X-Forwarded-For", c.RealIP())
	c.Request().Header.Set("X-Forwarded-Proto", scheme)

	// Important: Keep the original host for the second FAST server
	c.Request().Host = originalHost

	// Execute the proxy middleware
	err = proxyMiddleware(func(c echo.Context) error {
		return nil
	})(c)

	if err != nil {
		c.Logger().Errorf("Proxy error: %v", err)
		return err
	}

	return nil
}
