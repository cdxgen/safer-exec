//go:build windows

package mxc

import (
	"math/rand"
	"slices"
	"testing"

	"golang.org/x/sys/windows"
)

// The reference parser in cmdline_test.go is checked against the real
// CommandLineToArgvW on Windows, and so is every command line ComposeCommandLine
// produces.
func TestComposeCommandLineMatchesCommandLineToArgvW(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	alphabet := []rune("ab \t\"\\%&|^<>!'*?;=é")
	prog := `C:\Program Files\nodejs\node.exe`
	for i := range 2000 {
		var args []string
		for range r.Intn(6) {
			b := make([]rune, r.Intn(9))
			for k := range b {
				b[k] = alphabet[r.Intn(len(alphabet))]
			}
			args = append(args, string(b))
		}
		cl, err := ComposeCommandLine(prog, args)
		if err != nil {
			t.Fatal(err)
		}
		got, err := windows.DecomposeCommandLine(cl)
		if err != nil {
			t.Fatalf("DecomposeCommandLine(%q): %v", cl, err)
		}
		want := append([]string{prog}, args...)
		if !slices.Equal(got, want) {
			t.Fatalf("case %d: %q parsed as %q, want %q", i, cl, got, want)
		}
		if ref := parseCommandLine(cl); !slices.Equal(ref, got) {
			t.Fatalf("reference parser disagrees on %q: %q vs %q", cl, ref, got)
		}
	}
}
