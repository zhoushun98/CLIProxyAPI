package quotapark

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrUnparkCollision indicates that the destination path for an unpark already
// exists and the operator likely restored the file manually. The caller should
// drop its in-memory state for this authID without overwriting the operator's
// copy.
var ErrUnparkCollision = errors.New("quotapark: unpark target already exists")

// mover translates park/unpark operations into atomic os.Rename calls. It is
// stateless apart from the configured directory pair, so callers may share a
// single instance.
type mover struct {
	authDir   string
	parkedDir string
}

// newMover constructs a mover. authDir must be an absolute path; parkSubdir is
// resolved relative to authDir.
func newMover(authDir, parkSubdir string) *mover {
	return &mover{
		authDir:   filepath.Clean(authDir),
		parkedDir: filepath.Join(filepath.Clean(authDir), parkSubdir),
	}
}

// AuthDir returns the resolved active auth directory.
func (m *mover) AuthDir() string { return m.authDir }

// ParkedDir returns the resolved parking directory.
func (m *mover) ParkedDir() string { return m.parkedDir }

// Park renames <authDir>/<base> into <parkedDir>/<base>. The parked dir is
// created with 0o700 on first use. Returns the absolute parked path.
func (m *mover) Park(authID string) (string, error) {
	base := sanitizeAuthBase(authID)
	if base == "" {
		return "", fmt.Errorf("quotapark: invalid auth id %q", authID)
	}
	src := filepath.Join(m.authDir, base)
	dst := filepath.Join(m.parkedDir, base)

	if err := os.MkdirAll(m.parkedDir, 0o700); err != nil {
		return "", fmt.Errorf("quotapark: mkdir %s: %w", m.parkedDir, err)
	}
	if err := os.Rename(src, dst); err != nil {
		return "", fmt.Errorf("quotapark: rename %s -> %s: %w", src, dst, err)
	}
	return dst, nil
}

// Unpark renames <parkedDir>/<base> back to <authDir>/<base>. If the active
// destination already exists, the parked copy is left in place and
// ErrUnparkCollision is returned.
func (m *mover) Unpark(authID string) (string, error) {
	base := sanitizeAuthBase(authID)
	if base == "" {
		return "", fmt.Errorf("quotapark: invalid auth id %q", authID)
	}
	src := filepath.Join(m.parkedDir, base)
	dst := filepath.Join(m.authDir, base)
	if _, err := os.Stat(dst); err == nil {
		return dst, ErrUnparkCollision
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("quotapark: stat %s: %w", dst, err)
	}
	if err := os.Rename(src, dst); err != nil {
		return "", fmt.Errorf("quotapark: rename %s -> %s: %w", src, dst, err)
	}
	return dst, nil
}

// sanitizeAuthBase rejects any value that contains path separators or "..".
// This is defensive in addition to Auth.ID already being a relative filename.
func sanitizeAuthBase(authID string) string {
	v := strings.TrimSpace(authID)
	if v == "" {
		return ""
	}
	if strings.ContainsAny(v, `/\`) {
		return ""
	}
	if v == "." || v == ".." || strings.Contains(v, "..") {
		return ""
	}
	return v
}
