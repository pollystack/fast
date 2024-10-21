package server

import (
	"crypto/tls"
	"fast/config"
	"fast/handlers"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Server struct {
	echo   *echo.Echo
	config *config.Config
}

// TemplateRenderer is a custom html/template renderer for Echo framework
type TemplateRenderer struct {
	templates *template.Template
}

// Render renders a template document
func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	// Add global methods if data is a map
	if viewContext, isMap := data.(map[string]interface{}); isMap {
		viewContext["reverse"] = c.Echo().Reverse
	}
	return t.templates.ExecuteTemplate(w, name, data)
}

func New(cfg *config.Config) *Server {
	e := echo.New()

	// Initialize and set the renderer
	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseGlob("templates/*.html")),
	}
	e.Renderer = renderer

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
		log.Printf("  - %s (Type: %s, Public Dir: %s)", domain.Name, domain.Type, domain.PublicDir)
	}
	s.setupRoutes()

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

func (s *Server) setupRoutes() {
	// Create a map for quick domain lookup
	domainMap := make(map[string]config.Domain)
	for _, domain := range s.config.Domains {
		domainMap[domain.Name] = domain
	}

	// Single middleware to handle all domains
	s.echo.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			host := c.Request().Host
			if strings.Contains(host, ":") {
				host = strings.Split(host, ":")[0]
			}
			log.Printf("Incoming request for host: %s", host)

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
				log.Printf("No matching domain found for host: %s", host)
				return echo.ErrNotFound
			}

			log.Printf("Matched domain: %s", matchedName)
			c.Set("domain", matchedDomain)
			return next(c)
		}
	})

	// Root handler
	s.echo.GET("/", func(c echo.Context) error {
		domain := c.Get("domain").(config.Domain)
		switch domain.Type {
		case "proxy":
			return handlers.HandleProxy(c, domain)
		case "file_directory":
			return handlers.HandleFileDirectory(c, domain)
		default:
			return handlers.ServeIndexOrFile(c, domain.PublicDir, "index.html")
		}
	})

	// Catch-all handler
	s.echo.GET("/*", func(c echo.Context) error {
		domain := c.Get("domain").(config.Domain)
		switch domain.Type {
		case "proxy":
			return handlers.HandleProxy(c, domain)
		case "file_directory":
			return handlers.HandleFileDirectory(c, domain)
		default:
			return handlers.ServeIndexOrFile(c, domain.PublicDir, c.Request().URL.Path)
		}
	})
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
