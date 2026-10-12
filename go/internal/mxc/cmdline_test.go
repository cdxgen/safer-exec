package mxc

import (
	"math/rand"
	"strings"
	"testing"
)

// parseCommandLine is a reference implementation of the Microsoft C runtime
// argument parser (the rules CommandLineToArgvW and msvcrt apply since
// Visual C++ 2008): the program name is read up to the next whitespace, or
// between quotes without escapes; in the arguments, 2n backslashes before a
// quote yield n backslashes and toggle quoting, 2n+1 yield n backslashes and
// a literal quote, and "" inside a quoted region yields a literal quote.
func parseCommandLine(cmd string) []string {
	var args []string
	i := 0
	// Program name.
	var prog strings.Builder
	if i < len(cmd) && cmd[i] == '"' {
		i++
		for i < len(cmd) && cmd[i] != '"' {
			prog.WriteByte(cmd[i])
			i++
		}
		if i < len(cmd) {
			i++
		}
	} else {
		for i < len(cmd) && cmd[i] != ' ' && cmd[i] != '\t' {
			prog.WriteByte(cmd[i])
			i++
		}
	}
	args = append(args, prog.String())

	for {
		for i < len(cmd) && (cmd[i] == ' ' || cmd[i] == '\t') {
			i++
		}
		if i >= len(cmd) {
			return args
		}
		var arg strings.Builder
		inQuotes := false
		for i < len(cmd) {
			c := cmd[i]
			if !inQuotes && (c == ' ' || c == '\t') {
				break
			}
			if c == '\\' {
				n := 0
				for i < len(cmd) && cmd[i] == '\\' {
					n++
					i++
				}
				if i < len(cmd) && cmd[i] == '"' {
					arg.WriteString(strings.Repeat(`\`, n/2))
					if n%2 == 1 {
						arg.WriteByte('"')
						i++
					}
				} else {
					arg.WriteString(strings.Repeat(`\`, n))
				}
				continue
			}
			if c == '"' {
				if inQuotes && i+1 < len(cmd) && cmd[i+1] == '"' {
					arg.WriteByte('"')
					i += 2
					continue
				}
				inQuotes = !inQuotes
				i++
				continue
			}
			arg.WriteByte(c)
			i++
		}
		args = append(args, arg.String())
	}
}

func TestEscapeArgVectors(t *testing.T) {
	cases := map[string]string{
		``:                    `""`,
		`plain`:               `plain`,
		`a b`:                 `"a b"`,
		"tab\there":           "\"tab\there\"",
		`a"b`:                 `a\"b`,
		`a\b`:                 `a\b`,
		`a\`:                  `a\`,
		`a b\`:                `"a b\\"`,
		`a\"b`:                `a\\\"b`,
		`a\\"b c`:             `"a\\\\\"b c"`,
		`C:\Program Files\x\`: `"C:\Program Files\x\\"`,
	}
	for in, want := range cases {
		if got := EscapeArg(in); got != want {
			t.Errorf("EscapeArg(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestComposeCommandLineRoundTrip(t *testing.T) {
	fixed := [][]string{
		{"install"},
		{"", "a b", `a"b`, `a\`, `a b\`, `\\server\share\`, `"`, `\"`, `\\"`, "x\ty", " leading", "trailing "},
		{`--flag="quoted value"`, `C:\Program Files\dir\`, `%PATH%`, `a&b|c<d>e^f`},
	}
	r := rand.New(rand.NewSource(1))
	alphabet := []byte("ab \t\"\\%&|^<>!'*?;=")
	for range 500 {
		n := r.Intn(5)
		var args []string
		for range n {
			l := r.Intn(8)
			b := make([]byte, l)
			for k := range b {
				b[k] = alphabet[r.Intn(len(alphabet))]
			}
			args = append(args, string(b))
		}
		fixed = append(fixed, args)
	}
	prog := `C:\Program Files\nodejs\node.exe`
	for _, args := range fixed {
		cl, err := ComposeCommandLine(prog, args)
		if err != nil {
			t.Fatalf("ComposeCommandLine(%q): %v", args, err)
		}
		got := parseCommandLine(cl)
		want := append([]string{prog}, args...)
		if len(got) != len(want) {
			t.Fatalf("round trip of %q via %q: got %q", want, cl, got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("round trip of %q via %q: got %q", want, cl, got)
			}
		}
	}
}

func TestComposeCommandLineRejects(t *testing.T) {
	for _, prog := range []string{``, `C:\a"b.exe`, `C:\dir\`, "C:\\x\x00.exe"} {
		if _, err := ComposeCommandLine(prog, nil); err == nil {
			t.Errorf("program %q accepted", prog)
		}
	}
	if _, err := ComposeCommandLine(`C:\x.exe`, []string{"a\x00b"}); err == nil {
		t.Error("NUL argument accepted")
	}
	cl, err := ComposeCommandLine(`C:\Program Files\x.exe`, nil)
	if err != nil || cl != `"C:\Program Files\x.exe"` {
		t.Errorf("program is not always quoted: %q, %v", cl, err)
	}
}

func TestComposeBatchCommandLine(t *testing.T) {
	cmdExe := `C:\Windows\System32\cmd.exe`
	cases := []struct {
		args []string
		want string
	}{
		{nil, `"C:\Windows\System32\cmd.exe" /d /e:ON /v:OFF /c ""C:\n\npm.cmd""`},
		{[]string{"install", "--save-dev"}, `"C:\Windows\System32\cmd.exe" /d /e:ON /v:OFF /c ""C:\n\npm.cmd" install --save-dev"`},
		{[]string{"x&echo INJECTED"}, `"C:\Windows\System32\cmd.exe" /d /e:ON /v:OFF /c ""C:\n\npm.cmd" "x&echo INJECTED""`},
		{[]string{"%PATH%"}, `"C:\Windows\System32\cmd.exe" /d /e:ON /v:OFF /c ""C:\n\npm.cmd" "%%cd:~,%PATH%%cd:~,%""`},
		{[]string{`"&calc&"`}, `"C:\Windows\System32\cmd.exe" /d /e:ON /v:OFF /c ""C:\n\npm.cmd" """&calc&""""`},
		{[]string{`a b\`}, `"C:\Windows\System32\cmd.exe" /d /e:ON /v:OFF /c ""C:\n\npm.cmd" "a b\\""`},
		{[]string{``}, `"C:\Windows\System32\cmd.exe" /d /e:ON /v:OFF /c ""C:\n\npm.cmd" """`},
		// '=' separates arguments in cmd's batch parameter parsing, so it is quoted.
		{[]string{`C:\path\x.js`, `--opt=1`}, `"C:\Windows\System32\cmd.exe" /d /e:ON /v:OFF /c ""C:\n\npm.cmd" C:\path\x.js "--opt=1""`},
		{[]string{`!VAR!`}, `"C:\Windows\System32\cmd.exe" /d /e:ON /v:OFF /c ""C:\n\npm.cmd" "!VAR!""`},
	}
	for _, c := range cases {
		got, err := ComposeBatchCommandLine(cmdExe, `C:\n\npm.cmd`, c.args)
		if err != nil {
			t.Fatalf("ComposeBatchCommandLine(%q): %v", c.args, err)
		}
		if got != c.want {
			t.Errorf("ComposeBatchCommandLine(%q)\n got %s\nwant %s", c.args, got, c.want)
		}
	}
}

func TestComposeBatchCommandLineRejects(t *testing.T) {
	cmdExe := `C:\Windows\System32\cmd.exe`
	for _, arg := range []string{"a\nb", "a\rb", "a\x00b"} {
		if _, err := ComposeBatchCommandLine(cmdExe, `C:\x.cmd`, []string{arg}); err == nil {
			t.Errorf("argument %q accepted", arg)
		}
	}
	for _, script := range []string{`C:\100%\x.cmd`, `C:\a"b.cmd`, `C:\dir\`, ``} {
		if _, err := ComposeBatchCommandLine(cmdExe, script, nil); err == nil {
			t.Errorf("script %q accepted", script)
		}
	}
}

func TestIsBatchFile(t *testing.T) {
	for in, want := range map[string]bool{
		`C:\x\npm.cmd`: true, `C:\x\a.BAT`: true, `C:\x\node.exe`: false, `C:\x\cmd`: false,
	} {
		if got := IsBatchFile(in); got != want {
			t.Errorf("IsBatchFile(%q) = %v", in, got)
		}
	}
}

func TestLookPath(t *testing.T) {
	files := map[string]bool{
		`c:\windows\system32\cmd.exe`:      true,
		`c:\program files\nodejs\node.exe`: true,
		`c:\program files\nodejs\npm.cmd`:  true,
		`c:\program files\nodejs\npm`:      true, // POSIX shim, not launchable
		`c:\tools\bin\tool.py`:             true,
		`c:\tools\bin\both.bat`:            true,
		`c:\tools\bin\both.exe`:            true,
		`c:\work\proj\run.cmd`:             true,
		`c:\work\proj\cmd.exe`:             true, // planted in the working dir
		`c:\work\proj\bin\local.exe`:       true,
		`c:\work\proj\script.ps1`:          true,
	}
	opts := LookPathOptions{
		PathList: `C:\Windows\system32;"C:\Program Files\nodejs";relative\dir;;C:\tools\bin`,
		PathExt:  `.COM;.EXE;.BAT;.CMD;.PY`,
		Dir:      `C:\work\proj`,
		IsFile:   func(p string) bool { return files[strings.ToLower(WinClean(p))] },
	}
	cases := map[string]string{
		"cmd":                  `C:\Windows\system32\cmd.exe`,
		"cmd.exe":              `C:\Windows\system32\cmd.exe`,
		"node":                 `C:\Program Files\nodejs\node.exe`,
		"npm":                  `C:\Program Files\nodejs\npm.cmd`,
		"both":                 `C:\tools\bin\both.exe`, // PATHEXT order: .EXE before .BAT
		`.\run.cmd`:            `C:\work\proj\run.cmd`,
		`bin\local`:            `C:\work\proj\bin\local.exe`,
		`C:\work\proj\run`:     `C:\work\proj\run.cmd`,
		`c:/work/proj/run.cmd`: `C:\work\proj\run.cmd`,
	}
	for name, want := range cases {
		got, err := LookPath(name, opts)
		if err != nil {
			t.Errorf("LookPath(%q): %v", name, err)
			continue
		}
		if !strings.EqualFold(got, want) {
			t.Errorf("LookPath(%q) = %q, want %q", name, got, want)
		}
	}
	for _, name := range []string{"tool", "missing", "script.ps1", `\rooted`, "", "a\x00b"} {
		if got, err := LookPath(name, opts); err == nil {
			t.Errorf("LookPath(%q) = %q, want error", name, got)
		}
	}
}

func TestComposeCmdCommandLine(t *testing.T) {
	cmdExe := `C:\Windows\System32\cmd.exe`
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"/c", `echo data> "C:\a b\x.txt"`}, `"C:\Windows\System32\cmd.exe" /d /s /c "echo data> "C:\a b\x.txt""`},
		{[]string{"/d", "/s", "/C", `"tool.exe" --flag`}, `"C:\Windows\System32\cmd.exe" /d /s /C ""tool.exe" --flag"`},
		{[]string{"/c", "echo", "a", "b"}, `"C:\Windows\System32\cmd.exe" /d /s /c "echo a b"`},
		// More than two quotes: /S strips only the outer pair.
		{[]string{"/c", `"C:\Program Files\nodejs\node.exe" -e "x"`}, `"C:\Windows\System32\cmd.exe" /d /s /c ""C:\Program Files\nodejs\node.exe" -e "x""`},
		{[]string{"/q", "/c", "ver"}, `"C:\Windows\System32\cmd.exe" /q /d /s /c "ver"`},
		{[]string{"/k"}, `"C:\Windows\System32\cmd.exe" /d /s /k`},
		{[]string{"/q", "/v:off"}, `"C:\Windows\System32\cmd.exe" /q /v:off`},
	}
	for _, c := range cases {
		got, err := ComposeCmdCommandLine(cmdExe, c.args)
		if err != nil || got != c.want {
			t.Errorf("ComposeCmdCommandLine(%q)\n got %s (%v)\nwant %s", c.args, got, err, c.want)
		}
	}
	if _, err := ComposeCmdCommandLine(cmdExe, []string{"/c", "a\x00b"}); err == nil {
		t.Error("NUL accepted")
	}
	if !IsCmdExe(`c:\windows\system32\CMD.EXE`) || IsCmdExe(`C:\x\cmd.exe.bak`) || IsCmdExe(`C:\x\npm.cmd`) {
		t.Error("IsCmdExe")
	}
}
