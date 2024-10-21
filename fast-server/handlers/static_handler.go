package handlers

import (
	"github.com/labstack/echo/v4"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func ServeIndexOrFile(c echo.Context, publicDir, requestPath string) error {
	fullPath := filepath.Join(publicDir, filepath.Clean(requestPath))

	// Prevent directory traversal
	if !strings.HasPrefix(fullPath, publicDir) {
		log.Printf("Attempted directory traversal detected: %s", fullPath)
		return echo.ErrNotFound
	}

	if stat, err := os.Stat(fullPath); err == nil && !stat.IsDir() {
		log.Printf("Serving file: %s", fullPath)
		return c.File(fullPath)
	}

	// If file doesn't exist or is a directory, serve the root index.html
	indexPath := filepath.Join(publicDir, "index.html")
	log.Printf("Serving index.html: %s", indexPath)
	return c.File(indexPath)
}
