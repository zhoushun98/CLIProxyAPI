package quotapark

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMoverParkCreatesDisabledDir(t *testing.T) {
	dir := t.TempDir()
	authID := "codex-foo.json"
	writeFile(t, filepath.Join(dir, authID), `{"type":"codex"}`)

	mv := newMover(dir, ".disabled")
	parked, err := mv.Park(authID)
	if err != nil {
		t.Fatalf("Park: %v", err)
	}
	expected := filepath.Join(dir, ".disabled", authID)
	if parked != expected {
		t.Fatalf("parked path = %s, want %s", parked, expected)
	}
	if _, statErr := os.Stat(expected); statErr != nil {
		t.Fatalf("parked file missing: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(dir, authID)); !os.IsNotExist(statErr) {
		t.Fatalf("original file should be gone after park, stat err = %v", statErr)
	}
}

func TestMoverParkInvalidAuthID(t *testing.T) {
	dir := t.TempDir()
	mv := newMover(dir, ".disabled")
	for _, id := range []string{"", "../escape.json", "foo/bar.json", `back\slash.json`, ".."} {
		if _, err := mv.Park(id); err == nil {
			t.Errorf("Park %q must reject", id)
		}
	}
}

func TestMoverUnparkRestoresFile(t *testing.T) {
	dir := t.TempDir()
	authID := "codex-foo.json"
	parkedDir := filepath.Join(dir, ".disabled")
	if err := os.MkdirAll(parkedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(parkedDir, authID), `{"type":"codex"}`)

	mv := newMover(dir, ".disabled")
	dst, err := mv.Unpark(authID)
	if err != nil {
		t.Fatalf("Unpark: %v", err)
	}
	if dst != filepath.Join(dir, authID) {
		t.Fatalf("unparked path = %s, want %s", dst, filepath.Join(dir, authID))
	}
	if _, statErr := os.Stat(dst); statErr != nil {
		t.Fatalf("unparked file missing: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(parkedDir, authID)); !os.IsNotExist(statErr) {
		t.Fatalf("parked file should be gone after unpark, stat err = %v", statErr)
	}
}

func TestMoverUnparkCollision(t *testing.T) {
	dir := t.TempDir()
	authID := "codex-foo.json"
	parkedDir := filepath.Join(dir, ".disabled")
	if err := os.MkdirAll(parkedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(parkedDir, authID), `{"parked":true}`)
	writeFile(t, filepath.Join(dir, authID), `{"active":true}`)

	mv := newMover(dir, ".disabled")
	_, err := mv.Unpark(authID)
	if !errors.Is(err, ErrUnparkCollision) {
		t.Fatalf("expected ErrUnparkCollision, got %v", err)
	}
	// Parked copy must remain so the operator can inspect it.
	if _, statErr := os.Stat(filepath.Join(parkedDir, authID)); statErr != nil {
		t.Fatalf("parked file should remain after collision, stat err = %v", statErr)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
