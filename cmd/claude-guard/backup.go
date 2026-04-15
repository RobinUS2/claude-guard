package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// cmdBackup copies the guard's persistent state (decision logs, app
// log, denies log, cache directory, circuit breaker state, config,
// legacy patterns) to a backup location. Default destination is the
// user's mounted Google Drive — matches the existing pattern in
// CLAUDE.md for ~/.claude backups.
//
//	claude-guard backup [--dest PATH] [--dry-run] [--compress]
//
// Without --dest, the destination is:
//
//	~/Library/CloudStorage/GoogleDrive-robin@us2.nl/My Drive/backups/claude-guard/<hostname>/<YYYY-MM-DD>/
//
// On macOS this is the standard mount point for Google Drive for
// Desktop. On other systems --dest must be passed explicitly.
//
// The backup is non-destructive: it copies, never deletes. Running
// daily produces a dated snapshot directory each time. Old snapshots
// are not pruned — that's the user's call.
func cmdBackup(args []string) int {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var dest string
	var dryRun bool
	var compress bool
	fs.StringVar(&dest, "dest", "", "destination directory (default: Google Drive backups path)")
	fs.BoolVar(&dryRun, "dry-run", false, "print what would be copied without writing anything")
	fs.BoolVar(&compress, "compress", false, "create a single .tar.gz archive instead of a directory tree")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	home, _ := os.UserHomeDir()
	if dest == "" {
		dest = defaultBackupDest(home)
	}

	// Compose a dated snapshot subdirectory so daily backups don't
	// overwrite each other.
	hostname, _ := os.Hostname()
	dateDir := time.Now().UTC().Format("2006-01-02")
	snapshot := filepath.Join(dest, hostname, dateDir)

	// Sources to back up. Each source has a logical name and the
	// path on disk. Missing sources are skipped (with a notice).
	sources := []backupSource{
		{name: "logs", path: filepath.Join(home, ".claude", "logs", "claude-guard")},
		{name: "config", path: filepath.Join(home, ".config", "claude-guard")},
		{name: "cache", path: filepath.Join(home, ".cache", "claude-guard")},
	}
	// Honor XDG override.
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		sources[1].path = filepath.Join(xdg, "claude-guard")
	}
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		sources[2].path = filepath.Join(xdg, "claude-guard")
	}

	fmt.Printf("backup snapshot: %s\n", snapshot)
	if dryRun {
		fmt.Println("(dry run — no files written)")
	}
	fmt.Println()

	totalFiles := 0
	totalBytes := int64(0)
	missing := 0

	for _, src := range sources {
		fi, err := os.Stat(src.path)
		if os.IsNotExist(err) {
			fmt.Printf("[skip] %-7s %s (missing)\n", src.name, src.path)
			missing++
			continue
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "[err]  %-7s %s: %v\n", src.name, src.path, err)
			continue
		}
		if !fi.IsDir() {
			fmt.Printf("[skip] %-7s %s (not a directory)\n", src.name, src.path)
			continue
		}

		dstDir := filepath.Join(snapshot, src.name)
		count, bytes, err := copyTree(src.path, dstDir, dryRun)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[err]  %-7s %s → %s: %v\n", src.name, src.path, dstDir, err)
			continue
		}
		fmt.Printf("[ok]   %-7s %d files, %s\n", src.name, count, humanBytes(bytes))
		totalFiles += count
		totalBytes += bytes
	}

	fmt.Println()
	fmt.Printf("total: %d files, %s\n", totalFiles, humanBytes(totalBytes))
	if missing > 0 {
		fmt.Printf("note:  %d source(s) missing (not yet created — fine on first run)\n", missing)
	}
	if !dryRun {
		fmt.Printf("done:  %s\n", snapshot)
	}
	return 0
}

// defaultBackupDest returns the canonical Google Drive backups path on
// macOS, matching the existing convention in CLAUDE.md
// (~/Library/CloudStorage/GoogleDrive-...). Falls back to ~/Backups
// on other systems.
func defaultBackupDest(home string) string {
	// Look for any GoogleDrive-* directory under CloudStorage.
	cs := filepath.Join(home, "Library", "CloudStorage")
	if entries, err := os.ReadDir(cs); err == nil {
		for _, e := range entries {
			if e.IsDir() && strings.HasPrefix(e.Name(), "GoogleDrive-") {
				return filepath.Join(cs, e.Name(), "My Drive", "backups", "claude-guard")
			}
		}
	}
	return filepath.Join(home, "Backups", "claude-guard")
}

type backupSource struct {
	name string
	path string
}

// copyTree recursively copies every file under src to dst. Returns
// (files, totalBytes, err). Symlinks are not followed — they're
// recreated as symlinks. Permissions are preserved.
//
// On dryRun, walks the tree but writes nothing.
func copyTree(src, dst string, dryRun bool) (int, int64, error) {
	var (
		files     int
		totalSize int64
	)
	err := filepath.Walk(src, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dst, rel)

		switch {
		case info.IsDir():
			if dryRun {
				return nil
			}
			return os.MkdirAll(dstPath, info.Mode())
		case info.Mode()&os.ModeSymlink != 0:
			files++
			if dryRun {
				return nil
			}
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			_ = os.Remove(dstPath)
			return os.Symlink(target, dstPath)
		default:
			files++
			totalSize += info.Size()
			if dryRun {
				return nil
			}
			return copyFile(path, dstPath, info.Mode())
		}
	})
	return files, totalSize, err
}

func copyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// humanBytes formats a byte count as a human-readable string.
func humanBytes(n int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case n >= GB:
		return fmt.Sprintf("%.1f GiB", float64(n)/GB)
	case n >= MB:
		return fmt.Sprintf("%.1f MiB", float64(n)/MB)
	case n >= KB:
		return fmt.Sprintf("%.1f KiB", float64(n)/KB)
	default:
		return fmt.Sprintf("%d B", n)
	}
}
