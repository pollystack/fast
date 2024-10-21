package handlers

import (
	"fast/config"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

type FileInfo struct {
	Name         string
	IsDir        bool
	Size         int64
	LastModified time.Time
}

func (f FileInfo) FormattedSize() string {
	if f.IsDir {
		return "-"
	}
	const unit = 1024
	if f.Size < unit {
		return fmt.Sprintf("%d B", f.Size)
	}
	div, exp := int64(unit), 0
	for n := f.Size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(f.Size)/float64(div), "KMGTPE"[exp])
}

func (f FileInfo) FormattedDate() string {
	return f.LastModified.Format("2006-01-02 15:04:05")
}

func HandleFileDirectory(c echo.Context, domain config.Domain) error {
	path := c.Param("*")
	fullPath := filepath.Join(domain.PublicDir, path)

	// Prevent directory traversal
	if !strings.HasPrefix(fullPath, domain.PublicDir) {
		return echo.ErrNotFound
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		return echo.ErrNotFound
	}

	if info.IsDir() {
		return serveDirectory(c, fullPath, path, domain.Name)
	}

	return serveFile(c, fullPath, info)
}

func serveDirectory(c echo.Context, fullPath, relativePath, domainName string) error {
	files, err := ioutil.ReadDir(fullPath)
	if err != nil {
		return echo.ErrInternalServerError
	}

	var fileInfos []FileInfo
	for _, f := range files {
		fileInfos = append(fileInfos, FileInfo{
			Name:         f.Name(),
			IsDir:        f.IsDir(),
			Size:         f.Size(),
			LastModified: f.ModTime(),
		})
	}

	sort.Slice(fileInfos, func(i, j int) bool {
		if fileInfos[i].IsDir == fileInfos[j].IsDir {
			return fileInfos[i].Name < fileInfos[j].Name
		}
		return fileInfos[i].IsDir
	})

	return c.Render(http.StatusOK, "file_directory.html", map[string]interface{}{
		"DomainName":  domainName,
		"CurrentPath": relativePath,
		"ParentPath":  filepath.Dir(relativePath),
		"Files":       fileInfos,
	})
}

func serveFile(c echo.Context, filePath string, info os.FileInfo) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	c.Response().Header().Set("Accept-Ranges", "bytes")
	c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(filePath)))

	rangeHeader := c.Request().Header.Get("Range")
	if rangeHeader != "" {
		if strings.Contains(rangeHeader, ",") {
			return c.String(http.StatusRequestedRangeNotSatisfiable, "Multiple ranges are not supported")
		}

		parts := strings.Split(strings.TrimPrefix(rangeHeader, "bytes="), "-")
		if len(parts) != 2 {
			return c.String(http.StatusBadRequest, "Invalid range header")
		}

		start, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return c.String(http.StatusBadRequest, "Invalid range start")
		}

		var end int64
		if parts[1] != "" {
			end, err = strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return c.String(http.StatusBadRequest, "Invalid range end")
			}
		} else {
			end = info.Size() - 1
		}

		if start >= info.Size() || end >= info.Size() || start > end {
			return c.String(http.StatusRequestedRangeNotSatisfiable, "Invalid range")
		}

		c.Response().Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, info.Size()))
		c.Response().Header().Set("Content-Length", fmt.Sprintf("%d", end-start+1))
		c.Response().WriteHeader(http.StatusPartialContent)

		_, err = file.Seek(start, io.SeekStart)
		if err != nil {
			return err
		}

		_, err = io.CopyN(c.Response().Writer, file, end-start+1)
		return err
	}

	c.Response().Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	c.Response().WriteHeader(http.StatusOK)
	_, err = io.Copy(c.Response().Writer, file)
	return err
}
