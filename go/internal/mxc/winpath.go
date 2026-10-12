package mxc

import (
	"strings"
)

// Windows path helpers.
//
// The translation layer runs inside the Windows engine, but it is also unit
// tested on macOS and Linux, where path/filepath applies POSIX rules (a
// backslash is an ordinary character there). These helpers therefore implement
// the subset of Windows path semantics the translator needs, independent of the
// build host: drive-letter and UNC volumes, both separators, lexical cleaning,
// and case-insensitive containment.

// winVolumeLen returns the length of the volume prefix of p ("C:" or
// "\\server\share") after separators have been normalized to backslashes, or 0
// when p has no volume.
func winVolumeLen(p string) int {
	if len(p) >= 2 && p[1] == ':' && isASCIILetter(p[0]) {
		return 2
	}
	if len(p) >= 2 && p[0] == '\\' && p[1] == '\\' {
		// \\server\share
		rest := p[2:]
		server := strings.IndexByte(rest, '\\')
		if server <= 0 {
			return 0
		}
		share := rest[server+1:]
		if share == "" || share[0] == '\\' {
			return 0
		}
		end := strings.IndexByte(share, '\\')
		if end < 0 {
			return len(p)
		}
		return 2 + server + 1 + end
	}
	return 0
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// stripVerbatimPrefix removes the Win32 file-namespace prefix from a path that
// already uses backslashes: "\\?\C:\x" becomes "C:\x" and "\\?\UNC\srv\share"
// becomes "\\srv\share". Device paths ("\\.\") are returned unchanged.
func stripVerbatimPrefix(p string) string {
	if strings.HasPrefix(p, `\\?\`) {
		rest := p[4:]
		if len(rest) >= 4 && strings.EqualFold(rest[:4], `UNC\`) {
			return `\\` + rest[4:]
		}
		return rest
	}
	return p
}

// IsDevicePath reports whether p names a Win32 device namespace object such
// as "\\.\PhysicalDrive0" or "\\.\pipe\x". Those are never valid policy paths.
func IsDevicePath(p string) bool {
	q := strings.ReplaceAll(p, "/", `\`)
	return strings.HasPrefix(q, `\\.\`)
}

// WinIsAbs reports whether p is a fully qualified Windows path: a drive letter
// followed by a separator, or a UNC path. Rooted paths without a drive
// ("\foo", "/usr/lib") and drive-relative paths ("C:foo") are not absolute.
func WinIsAbs(p string) bool {
	q := stripVerbatimPrefix(strings.ReplaceAll(p, "/", `\`))
	n := winVolumeLen(q)
	if n == 0 {
		return false
	}
	if n == 2 { // drive letter
		return len(q) > 2 && q[2] == '\\'
	}
	return true // UNC
}

// WinIsRootedWithoutVolume reports whether p is rooted at the current drive
// ("\foo" or "/usr/lib"). Such paths usually come from cross-platform policies
// written for POSIX hosts.
func WinIsRootedWithoutVolume(p string) bool {
	q := strings.ReplaceAll(p, "/", `\`)
	return len(q) > 0 && q[0] == '\\' && !strings.HasPrefix(q, `\\`)
}

// WinClean returns the shortest lexically equivalent Windows path: forward
// slashes become backslashes, repeated separators collapse, "." elements are
// dropped and ".." elements are resolved without walking above the volume
// root. A drive letter is upper-cased. A trailing separator is removed unless
// the result is a volume root ("C:\").
func WinClean(p string) string {
	if p == "" {
		return ""
	}
	q := stripVerbatimPrefix(strings.ReplaceAll(p, "/", `\`))
	vol := winVolumeLen(q)
	volume := q[:vol]
	if vol == 2 {
		volume = strings.ToUpper(volume[:1]) + ":"
	}
	rest := q[vol:]
	rooted := strings.HasPrefix(rest, `\`) || (vol > 2) // UNC paths are always rooted

	var parts []string
	for elem := range strings.SplitSeq(rest, `\`) {
		switch elem {
		case "", ".":
			continue
		case "..":
			if len(parts) > 0 && parts[len(parts)-1] != ".." {
				parts = parts[:len(parts)-1]
			} else if !rooted {
				parts = append(parts, "..")
			}
		default:
			parts = append(parts, elem)
		}
	}
	joined := strings.Join(parts, `\`)
	switch {
	case rooted && vol > 2: // UNC
		if joined == "" {
			return volume + `\`
		}
		return volume + `\` + joined
	case rooted:
		return volume + `\` + joined
	case joined == "" && volume == "":
		return "."
	default:
		return volume + joined
	}
}

// WinJoin joins elem onto base with a backslash and cleans the result. If
// elem is itself absolute it is returned cleaned.
func WinJoin(base string, elem ...string) string {
	p := base
	for _, e := range elem {
		if e == "" {
			continue
		}
		if WinIsAbs(e) {
			p = e
			continue
		}
		if p == "" {
			p = e
		} else {
			p = p + `\` + e
		}
	}
	return WinClean(p)
}

// WinDir returns all but the last element of a cleaned Windows path. The
// directory of a volume root is the root itself.
func WinDir(p string) string {
	c := WinClean(p)
	vol := winVolumeLen(c)
	i := strings.LastIndexByte(c, '\\')
	if i < vol {
		return c
	}
	if i == vol { // "C:\file" -> "C:\"
		return c[:vol+1]
	}
	return c[:i]
}

// WinBase returns the last element of a Windows path.
func WinBase(p string) string {
	c := WinClean(p)
	if i := strings.LastIndexByte(c, '\\'); i >= 0 {
		return c[i+1:]
	}
	if winVolumeLen(c) == 2 {
		return c[2:]
	}
	return c
}

// WinExt returns the lower-cased extension of the last path element,
// including the leading dot, or "" when there is none.
func WinExt(p string) string {
	base := WinBase(p)
	if i := strings.LastIndexByte(base, '.'); i > 0 {
		return strings.ToLower(base[i:])
	}
	return ""
}

// WinIsVolumeRoot reports whether a cleaned absolute path is a volume root
// such as "C:\" or "\\server\share\".
func WinIsVolumeRoot(p string) bool {
	c := WinClean(p)
	vol := winVolumeLen(c)
	return vol > 0 && len(c) == vol+1 && c[vol] == '\\'
}

// WinEqual compares two Windows paths case-insensitively after cleaning.
func WinEqual(a, b string) bool {
	return strings.EqualFold(WinClean(a), WinClean(b))
}

// WinHasPrefix reports whether path p equals dir or lies beneath it, comparing
// case-insensitively on element boundaries ("C:\ab" is not under "C:\a").
func WinHasPrefix(p, dir string) bool {
	cp, cd := WinClean(p), WinClean(dir)
	if strings.EqualFold(cp, cd) {
		return true
	}
	if !strings.HasSuffix(cd, `\`) {
		cd += `\`
	}
	return len(cp) > len(cd) && strings.EqualFold(cp[:len(cd)], cd)
}

// SplitPathList splits a Windows PATH value the way Windows does: on
// semicolons outside double quotes, with the quotes removed, so a quoted
// entry may itself contain ';'. Entries are trimmed of surrounding spaces;
// empty entries are kept as "" for the caller to skip.
func SplitPathList(list string) []string {
	if list == "" {
		return nil
	}
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range list {
		switch {
		case r == '"':
			quoted = !quoted
		case r == ';' && !quoted:
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(out, strings.TrimSpace(cur.String()))
}
