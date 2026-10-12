//go:build windows

package mxc

import (
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
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

// Batch arguments must reach the script as literal data through the real
// cmd.exe, with no command injection and no %VAR% expansion. This runs
// without MXC, so CI checks the quoting even where the engine tests skip.
func TestComposeBatchCommandLineThroughRealCmd(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "args.cmd")
	// %1..%5 (not %~1) echo each argument as received, quotes included.
	body := "@echo off\r\n" +
		"echo [%1]\r\necho [%2]\r\necho [%3]\r\necho [%4]\r\necho [%5]\r\n"
	if err := os.WriteFile(script, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "injected.txt")
	args := []string{"plain", "x&echo pwned>" + marker, "%PATH%", "a b", `"&calc&"`}
	cmdExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	cl, err := ComposeBatchCommandLine(cmdExe, script, args)
	if err != nil {
		t.Fatal(err)
	}
	out := runCommandLine(t, cmdExe, cl)
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("argument injected a command; output:\n%s", out)
	}
	// %1 keeps the quotes the argument was passed with.
	for _, want := range []string{"[plain]", `["%PATH%"]`, `["a b"]`} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, `C:\Windows`) {
		t.Errorf("%%PATH%% was expanded:\n%s", out)
	}
}

// An explicit "cmd /c" runs its arguments as one shell command string with
// any number of embedded quotes.
func TestComposeCmdCommandLineThroughRealCmd(t *testing.T) {
	cmdExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	where := filepath.Join(os.Getenv("SystemRoot"), "System32", "where.exe")
	cl, err := ComposeCmdCommandLine(cmdExe, []string{"/c", `"` + where + `" "cmd.exe" && echo second-command`})
	if err != nil {
		t.Fatal(err)
	}
	out := runCommandLine(t, cmdExe, cl)
	if !strings.Contains(strings.ToLower(out), `\cmd.exe`) || !strings.Contains(out, "second-command") {
		t.Errorf("command string mangled (%s):\n%s", cl, out)
	}
}

func runCommandLine(t *testing.T, program, commandLine string) string {
	t.Helper()
	c := exec.Command(program)
	c.SysProcAttr = &syscall.SysProcAttr{CmdLine: commandLine}
	out, err := c.CombinedOutput()
	if err != nil {
		t.Logf("%s: %v", commandLine, err)
	}
	return string(out)
}
