// Package web embeds the dashboard so the Leash binary is self-contained.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:static
var files embed.FS

// Handler serves the dashboard files.
func Handler() http.Handler {
	sub, err := fs.Sub(files, "static")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}
