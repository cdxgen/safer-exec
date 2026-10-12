package mxc

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// MXC's ProcessContainer backend hands process.commandLine straight to
// CreateProcessW with a NULL lpApplicationName, so the string is split by the
// Windows loader (first token) and the program's C runtime (the rest). The
// helpers here turn an argv vector into a command line that those parsers
// reconstruct exactly, and refuse argv that cannot be represented safely.

// launchableExts are the file types CreateProcess can start: PE images and,
// through an implicit cmd.exe, batch scripts. Other PATHEXT entries (.ps1,
// .py, .js, ...) are shell associations that CreateProcess does not honour.
var launchableExts = []string{".com", ".exe", ".bat", ".cmd"}

// IsBatchFile reports whether path names a cmd.exe batch script.
func IsBatchFile(path string) bool {
	ext := WinExt(path)
	return ext == ".bat" || ext == ".cmd"
}

func isLaunchableExt(ext string) bool {
	return slices.Contains(launchableExts, ext)
}

// EscapeArg quotes one argument so that CommandLineToArgvW and the Microsoft
// C runtime parse it back to exactly s. This is the documented MSVC algorithm
// (the same one Go's syscall.EscapeArg implements on Windows): backslashes are
// literal unless they precede a double quote, in which case they are doubled
// and the quote is escaped.
func EscapeArg(s string) string {
	if s == "" {
		return `""`
	}
	needsQuote := false
	needsEscape := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\n', '\v':
			needsQuote = true
		case '"', '\\':
			needsEscape = true
		}
	}
	if !needsQuote && !needsEscape {
		return s
	}
	if !needsEscape {
		return `"` + s + `"`
	}
	var b strings.Builder
	if needsQuote {
		b.WriteByte('"')
	}
	slashes := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			slashes++
		case '"':
			for ; slashes > 0; slashes-- {
				b.WriteByte('\\')
			}
			b.WriteByte('\\')
		default:
			slashes = 0
		}
		b.WriteByte(c)
	}
	if needsQuote {
		for ; slashes > 0; slashes-- {
			b.WriteByte('\\')
		}
		b.WriteByte('"')
	}
	return b.String()
}

// errInvalidProgram is returned for program paths that cannot be quoted as
// the first command-line token.
var errInvalidProgram = errors.New("program path must not contain '\"' or NUL and must not end with a backslash")

// quoteProgram renders the first command-line token. It is always quoted so a
// path with spaces can never be re-split by CreateProcess's search for an
// executable prefix ("C:\Program.exe" planted ahead of "C:\Program Files\x").
// Windows file names cannot contain '"', so no escaping is required.
func quoteProgram(path string) (string, error) {
	if path == "" || strings.ContainsAny(path, "\"\x00") || strings.HasSuffix(path, `\`) {
		return "", errInvalidProgram
	}
	return `"` + path + `"`, nil
}

// ComposeCommandLine renders program + args as a CreateProcess command line
// for a PE executable.
func ComposeCommandLine(program string, args []string) (string, error) {
	first, err := quoteProgram(program)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(first)
	for _, a := range args {
		if strings.ContainsRune(a, 0) {
			return "", fmt.Errorf("argument %q contains a NUL byte", a)
		}
		b.WriteByte(' ')
		b.WriteString(EscapeArg(a))
	}
	return b.String(), nil
}

// IsCmdExe reports whether path names the Windows command processor.
func IsCmdExe(path string) bool {
	return strings.EqualFold(WinBase(path), "cmd.exe")
}

// ComposeCmdCommandLine renders an explicit cmd.exe invocation. cmd.exe does
// not parse its command line with the C-runtime rules: after /C, /K or /R it
// takes the rest of the line as a command string, and a backslash-escaped
// quote is not an escape to it. Arguments before that switch are rendered
// with EscapeArg; everything after it is joined with spaces and passed
// verbatim, which is what a caller running "cmd /c <command>" means (Node's
// shell mode and Rust's raw_arg do the same). The command string is the
// caller's own script — argument hygiene for untrusted values is the job of
// ComposeBatchCommandLine, used when a .bat/.cmd file is the program.
func ComposeCmdCommandLine(cmdExe string, args []string) (string, error) {
	first, err := quoteProgram(cmdExe)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(first)
	for i, a := range args {
		if strings.ContainsRune(a, 0) {
			return "", fmt.Errorf("argument %q contains a NUL byte", a)
		}
		b.WriteByte(' ')
		switch strings.ToLower(a) {
		case "/c", "/k", "/r":
			b.WriteString(a)
			if rest := args[i+1:]; len(rest) > 0 {
				for _, r := range rest {
					if strings.ContainsRune(r, 0) {
						return "", fmt.Errorf("argument %q contains a NUL byte", r)
					}
				}
				b.WriteByte(' ')
				b.WriteString(strings.Join(rest, " "))
			}
			return b.String(), nil
		}
		b.WriteString(EscapeArg(a))
	}
	return b.String(), nil
}

// ComposeBatchCommandLine renders a batch-script invocation. CreateProcess
// runs .bat/.cmd files through an implicit "cmd.exe /c", whose parser expands
// %VAR% and treats &, |, <, >, ^ as operators even inside arguments that the
// C-runtime rules consider quoted — the "BatBadBut" class of argument
// injection. The script is therefore launched through an explicit cmd.exe
// with a command line built for cmd's own rules:
//
//   - /d skips the AutoRun registry hooks, /e:ON keeps command extensions on
//     (required by the %-neutralising construct below) and /v:OFF disables
//     delayed (!VAR!) expansion;
//   - every argument containing anything but a conservative set of safe
//     characters is wrapped in double quotes, with embedded quotes doubled;
//   - each '%' is rewritten to "%%cd:~,%", a zero-length substring of the
//     always-defined %cd% variable, so no %VAR% reference survives;
//   - CR and LF are rejected outright because cmd truncates the line there.
//
// This mirrors the hardened algorithm the Rust standard library adopted for
// CVE-2024-24576.
func ComposeBatchCommandLine(cmdExe, script string, args []string) (string, error) {
	first, err := quoteProgram(cmdExe)
	if err != nil {
		return "", err
	}
	if script == "" || strings.ContainsAny(script, "\"\x00") || strings.HasSuffix(script, `\`) {
		return "", fmt.Errorf("batch script path %q cannot be quoted for cmd.exe", script)
	}
	if strings.ContainsAny(script, "%\r\n") {
		// cmd.exe would expand %...% inside the quoted script path itself.
		return "", fmt.Errorf("batch script path %q contains a character cmd.exe cannot quote ('%%', CR or LF)", script)
	}

	var b strings.Builder
	b.WriteString(first)
	b.WriteString(` /d /e:ON /v:OFF /c ""`)
	b.WriteString(script)
	b.WriteByte('"')
	for _, a := range args {
		b.WriteByte(' ')
		if err := appendBatchArg(&b, a); err != nil {
			return "", err
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}

// batchUnquoted lists the ASCII punctuation that is safe outside quotes on a
// cmd.exe command line. Everything else (and every control character) forces
// quoting.
const batchUnquoted = `#$*+-./:?@\_`

func appendBatchArg(b *strings.Builder, arg string) error {
	if strings.ContainsAny(arg, "\r\n\x00") {
		return fmt.Errorf("argument %q contains CR, LF or NUL, which cannot be passed safely to a batch script", arg)
	}
	quote := arg == "" || strings.HasSuffix(arg, `\`)
	for _, r := range arg {
		if r < 0x80 {
			c := byte(r)
			if !(isASCIILetter(c) || (c >= '0' && c <= '9') || strings.IndexByte(batchUnquoted, c) >= 0) {
				quote = true
			}
		} else if unicode.IsControl(r) {
			quote = true
		}
	}
	if quote {
		b.WriteByte('"')
	}
	backslashes := 0
	for _, r := range arg {
		switch r {
		case '\\':
			backslashes++
			b.WriteRune(r)
			continue
		case '"':
			// 2n backslashes before an embedded quote, then double the quote.
			for i := 0; i < backslashes; i++ {
				b.WriteByte('\\')
			}
			b.WriteByte('"')
		case '%':
			b.WriteString("%%cd:~,")
		}
		backslashes = 0
		b.WriteRune(r)
	}
	if quote {
		for i := 0; i < backslashes; i++ {
			b.WriteByte('\\')
		}
		b.WriteByte('"')
	}
	return nil
}

// LookPathOptions configures LookPath.
type LookPathOptions struct {
	// PathList is the PATH value (';'-separated) to search for bare names.
	PathList string
	// PathExt is the PATHEXT value; only launchable extensions are honoured.
	PathExt string
	// Dir resolves relative paths (names containing a separator).
	Dir string
	// IsFile reports whether path exists and is a regular file.
	IsFile func(path string) bool
}

// LookPath resolves name the way CreateProcess would find it, but without the
// implicit current-directory and application-directory search: relative PATH
// entries are ignored and bare names are looked up only in absolute PATH
// directories, so a planted file in the working directory cannot shadow a
// system binary. Only launchable extensions (.com, .exe, .bat, .cmd) are
// considered, in PATHEXT order.
func LookPath(name string, opts LookPathOptions) (string, error) {
	if name == "" {
		return "", errors.New("empty command")
	}
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("command %q contains a NUL byte", name)
	}
	exts := launchableExtsFrom(opts.PathExt)

	if ext := WinExt(name); ext != "" && !isLaunchableExt(ext) && hasKnownSuffix(name, opts.PathExt) {
		return "", fmt.Errorf("%q is a %s file, which Windows cannot start directly; invoke it through its interpreter", name, ext)
	}

	candidates := func(base string) []string {
		var out []string
		if isLaunchableExt(WinExt(base)) {
			out = append(out, base)
		}
		for _, e := range exts {
			out = append(out, base+e)
		}
		return out
	}

	if strings.ContainsAny(name, `\/:`) {
		p := name
		if !WinIsAbs(p) {
			if WinIsRootedWithoutVolume(p) || !WinIsAbs(opts.Dir) {
				return "", fmt.Errorf("cannot resolve %q: not an absolute path", name)
			}
			p = WinJoin(opts.Dir, p)
		}
		p = WinClean(p)
		for _, c := range candidates(p) {
			if opts.IsFile(c) {
				return c, nil
			}
		}
		return "", fmt.Errorf("executable %q not found", p)
	}

	for dir := range strings.SplitSeq(opts.PathList, ";") {
		dir = strings.Trim(strings.TrimSpace(dir), `"`)
		if dir == "" || !WinIsAbs(dir) {
			continue
		}
		for _, c := range candidates(WinJoin(dir, name)) {
			if opts.IsFile(c) {
				return c, nil
			}
		}
	}
	return "", fmt.Errorf("executable %q not found in PATH", name)
}

// launchableExtsFrom returns the launchable extensions in PATHEXT order,
// falling back to the Windows default order when PATHEXT is empty.
func launchableExtsFrom(pathExt string) []string {
	var out []string
	seen := map[string]bool{}
	for e := range strings.SplitSeq(pathExt, ";") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" || !strings.HasPrefix(e, ".") || !isLaunchableExt(e) || seen[e] {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	if len(out) == 0 {
		return []string{".com", ".exe", ".bat", ".cmd"}
	}
	return out
}

// hasKnownSuffix reports whether name ends with an extension listed in
// PATHEXT (or a well-known script extension), i.e. the caller named a
// specific script type rather than a dotted base name such as "node.v20".
func hasKnownSuffix(name, pathExt string) bool {
	ext := WinExt(name)
	for e := range strings.SplitSeq(pathExt, ";") {
		if strings.EqualFold(strings.TrimSpace(e), ext) {
			return true
		}
	}
	switch ext {
	case ".ps1", ".py", ".js", ".vbs", ".wsf", ".sh", ".rb", ".pl", ".msc", ".lnk":
		return true
	}
	return false
}
