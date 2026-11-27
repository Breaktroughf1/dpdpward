// Package demo embeds the fictional demo application so `dpdpward demo`
// works from any install without a clone.
package demo

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed app db docs infra prisma src dpdpward.yaml
var files embed.FS

// WriteTo copies the demo application into dir, keeping its layout.
func WriteTo(dir string) error {
	return fs.WalkDir(files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(dir, filepath.FromSlash(p))
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := files.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
}
