package handlers

import (
	"fast/config"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"log"
	"net/url"
)

func HandleProxy(c echo.Context, domain config.Domain) error {
	target, err := url.Parse(fmt.Sprintf("http://%s:%d", domain.Proxy.Host, domain.Proxy.Port))
	if err != nil {
		log.Printf("Error parsing proxy URL: %v", err)
		return echo.ErrInternalServerError
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
	})

	return proxyMiddleware(func(c echo.Context) error {
		return nil
	})(c)
}
