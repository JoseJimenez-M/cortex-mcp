//go:build unix

package tools

import (
	"bytes"
	"log/slog"
	"os"
	"testing"
)

func TestMoveWarnsWhenBacklinkScanFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	var buf bytes.Buffer
	e := connectWith(t, func(d *Deps) { d.Logger = slog.New(slog.NewJSONHandler(&buf, nil)) })
	if err := os.WriteFile(e.dir+"/a.md", []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Write and search permission without read: the rename works, the
	// backlink walk cannot list the root.
	if err := os.Chmod(e.dir, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.dir, 0o755) })
	var out MoveOut
	decode(t, call(t, e, "move_note", map[string]any{"from": "a.md", "to": "b.md"}), &out)
	if out.BacklinksComplete {
		t.Fatal("backlinks_complete = true, want false")
	}
	lines := jsonLines(t, &buf)
	if len(lines) != 1 || lines[0]["level"] != "WARN" || lines[0]["from"] != "a.md" || lines[0]["to"] != "b.md" {
		t.Fatalf("log lines = %v", lines)
	}
}
