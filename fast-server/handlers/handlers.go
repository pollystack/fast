package handlers

import (
	"fast/config"
	"github.com/labstack/echo/v4"
)

func handleRequest(c echo.Context) error {
	domain := c.Get("domain").(config.Domain)
	switch domain.Type {
	case "proxy":
		return HandleProxy(c, domain)
	case "file_directory":
		return HandleFileDirectory(c, domain)
	default:
		return ServeIndexOrFile(c, domain.PublicDir, c.Request().URL.Path)
	}
}
