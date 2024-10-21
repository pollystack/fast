package handlers

import (
	"github.com/labstack/echo/v4"
	"os"
	"path/filepath"
	"strings"
)

func ServeIndexOrFile(c echo.Context, publicDir, requestPath string) error {
	fullPath := filepath.Join(publicDir, filepath.Clean(requestPath))

	// Prevent directory traversal
	if !strings.HasPrefix(fullPath, publicDir) {
		c.Logger().Warnf("Attempted directory traversal detected: %s", fullPath)
		return echo.ErrNotFound
	}

	if stat, err := os.Stat(fullPath); err == nil && !stat.IsDir() {
		c.Logger().Infof("Serving file: %s", fullPath)
		return c.File(fullPath)
	}

	// If file doesn't exist or is a directory, serve the root index.html
	indexPath := filepath.Join(publicDir, "index.html")
	c.Logger().Infof("Serving index.html: %s", indexPath)
	return c.File(indexPath)
}
