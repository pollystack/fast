package server

import (
	"crypto/tls"
	"fast/config"
	"fast/handlers"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"log"
	"net/http"
	"strings"
)

type Server struct {
	echo   *echo.Echo
	config *config.Config
}

func New(cfg *config.Config) *Server {
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	return &Server{
		echo:   e,
		config: cfg,
	}
}

func (s *Server) Start() error {
	log.Println("Setting up routes for domains:")
	for _, domain := range s.config.Domains {
		log.Printf("  - %s (Public Dir: %s)", domain.Name, domain.PublicDir)
	}
	handlers.SetupDomainRoutes(s.echo, s.config.Domains)

	// Add a catch-all route for all methods
	s.echo.Any("/*", func(c echo.Context) error {
		return echo.ErrNotFound
	})

	// Setup TLS config
	tlsConfig, err := s.setupTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to setup TLS config: %v", err)
	}

	// Start HTTP to HTTPS redirect
	go s.startHTTPRedirect()

	// Create custom server
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", s.config.Server.Port),
		TLSConfig: tlsConfig,
	}

	// Start HTTPS server
	return s.echo.StartServer(server)
}

func (s *Server) setupTLSConfig() (*tls.Config, error) {
	certificates := make(map[string]tls.Certificate)

	for _, domain := range s.config.Domains {
		cert, err := tls.LoadX509KeyPair(domain.SSL.CertFile, domain.SSL.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load SSL cert for %s: %v", domain.Name, err)
		}
		certificates[domain.Name] = cert
		log.Printf("Loaded certificate for domain: %s", domain.Name)
	}

	// Load global SSL certificate if provided
	if s.config.GlobalSSL.CertFile != "" && s.config.GlobalSSL.KeyFile != "" {
		globalCert, err := tls.LoadX509KeyPair(s.config.GlobalSSL.CertFile, s.config.GlobalSSL.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load global SSL cert: %v", err)
		}
		certificates[""] = globalCert
		log.Println("Loaded global SSL certificate")
	}

	return &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			log.Printf("Client requesting certificate for ServerName: %s", info.ServerName)

			if cert, ok := certificates[info.ServerName]; ok {
				return &cert, nil
			}

			// If no exact match, try to find a wildcard certificate
			for domainName, cert := range certificates {
				if strings.HasPrefix(domainName, "*.") && strings.HasSuffix(info.ServerName, domainName[1:]) {
					return &cert, nil
				}
			}

			// If still no match, return the global certificate if available
			if globalCert, ok := certificates[""]; ok {
				log.Printf("Using global certificate for ServerName: %s", info.ServerName)
				return &globalCert, nil
			}

			// As a last resort, return the first certificate in the map
			for _, cert := range certificates {
				log.Printf("Using first available certificate for ServerName: %s", info.ServerName)
				return &cert, nil
			}

			log.Printf("No suitable certificate found for ServerName: %s", info.ServerName)
			return nil, fmt.Errorf("no suitable certificate found")
		},
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		InsecureSkipVerify: s.config.IsDevelopment, // Only use this in development!
	}, nil
}

func (s *Server) startHTTPRedirect() {
	httpServer := &http.Server{
		Addr: fmt.Sprintf(":%d", s.config.Server.HTTPPort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+r.URL.String(), http.StatusMovedPermanently)
		}),
	}
	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
		s.echo.Logger.Fatal(err)
	}
}
