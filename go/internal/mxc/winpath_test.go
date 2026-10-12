package mxc

import "testing"

func TestWinIsAbs(t *testing.T) {
	cases := map[string]bool{
		`C:\x`:                 true,
		`c:/x/y`:               true,
		`C:\`:                  true,
		`C:`:                   false,
		`C:x`:                  false,
		`\x`:                   false,
		`/usr/lib`:             false,
		`relative\path`:        false,
		`\\srv\share`:          true,
		`\\srv\share\dir`:      true,
		`//srv/share/dir`:      true,
		`\\srv`:                false,
		`\\srv\`:               false,
		`\\?\C:\long\path`:     true,
		`\\?\UNC\srv\share\x`:  true,
		``:                     false,
		`~\x`:                  false,
		`1:\not-a-drive`:       false,
		`C:\x\..\..\..\escape`: true,
	}
	for in, want := range cases {
		if got := WinIsAbs(in); got != want {
			t.Errorf("WinIsAbs(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestWinClean(t *testing.T) {
	cases := map[string]string{
		`c:/a/./b/../c/`:           `C:\a\c`,
		`C:\`:                      `C:\`,
		`C:`:                       `C:`,
		`C:\..\..\x`:               `C:\x`,
		`C:\a\\\b`:                 `C:\a\b`,
		`\\srv\share\a\..\..\..`:   `\\srv\share\`,
		`\\srv\share\a\b\`:         `\\srv\share\a\b`,
		`\\?\C:\x\y`:               `C:\x\y`,
		`\\?\UNC\srv\share\x`:      `\\srv\share\x`,
		`a\..\..\b`:                `..\b`,
		`.`:                        `.`,
		`a\.`:                      `a`,
		``:                         ``,
		`\rooted\no\drive\..\x`:    `\rooted\no\x`,
		`C:\Program Files\nodejs\`: `C:\Program Files\nodejs`,
	}
	for in, want := range cases {
		if got := WinClean(in); got != want {
			t.Errorf("WinClean(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWinHasPrefix(t *testing.T) {
	cases := []struct {
		p, dir string
		want   bool
	}{
		{`C:\a\b`, `C:\a`, true},
		{`C:\a`, `C:\a`, true},
		{`c:\A\B`, `C:\a`, true},
		{`C:\ab`, `C:\a`, false},
		{`C:\a`, `C:\a\b`, false},
		{`C:\x`, `C:\`, true},
		{`D:\x`, `C:\`, false},
		{`\\srv\share\x`, `\\srv\share`, true},
		{`\\srv\share2\x`, `\\srv\share`, false},
		{`C:\a\..\b`, `C:\a`, false},
	}
	for _, c := range cases {
		if got := WinHasPrefix(c.p, c.dir); got != c.want {
			t.Errorf("WinHasPrefix(%q, %q) = %v, want %v", c.p, c.dir, got, c.want)
		}
	}
}

func TestWinDirBaseExt(t *testing.T) {
	if got := WinDir(`C:\a\b\c.exe`); got != `C:\a\b` {
		t.Errorf("WinDir = %q", got)
	}
	if got := WinDir(`C:\c.exe`); got != `C:\` {
		t.Errorf("WinDir(root file) = %q", got)
	}
	if got := WinDir(`C:\`); got != `C:\` {
		t.Errorf("WinDir(root) = %q", got)
	}
	if got := WinDir(`\\srv\share\x`); got != `\\srv\share\` {
		t.Errorf("WinDir(unc) = %q", got)
	}
	if got := WinBase(`C:\a\Node.EXE`); got != `Node.EXE` {
		t.Errorf("WinBase = %q", got)
	}
	if got := WinExt(`C:\a\Node.EXE`); got != `.exe` {
		t.Errorf("WinExt = %q", got)
	}
	if got := WinExt(`C:\a.b\noext`); got != `` {
		t.Errorf("WinExt(noext) = %q", got)
	}
	if got := WinExt(`.hidden`); got != `` {
		t.Errorf("WinExt(.hidden) = %q", got)
	}
}

func TestWinIsVolumeRoot(t *testing.T) {
	for in, want := range map[string]bool{
		`C:\`:            true,
		`c:/`:            true,
		`C:\x`:           false,
		`\\srv\share\`:   true,
		`\\srv\share`:    true, // a share name is always its own root
		`\\srv\share\x`:  false,
		`relative`:       false,
		`C:`:             false,
		`\\?\C:\`:        true,
		`C:\Windows\..\`: true,
	} {
		if got := WinIsVolumeRoot(in); got != want {
			t.Errorf("WinIsVolumeRoot(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestWinJoin(t *testing.T) {
	if got := WinJoin(`C:\a`, `b`, `..\c`); got != `C:\a\c` {
		t.Errorf("WinJoin = %q", got)
	}
	if got := WinJoin(`C:\a`, `D:\x`); got != `D:\x` {
		t.Errorf("WinJoin(abs) = %q", got)
	}
	if got := WinJoin(`C:\a`, ``); got != `C:\a` {
		t.Errorf("WinJoin(empty) = %q", got)
	}
}

func TestIsDevicePath(t *testing.T) {
	if !IsDevicePath(`\\.\PhysicalDrive0`) || !IsDevicePath(`//./pipe/x`) {
		t.Error("device paths not detected")
	}
	if IsDevicePath(`\\?\C:\x`) || IsDevicePath(`C:\x`) {
		t.Error("non-device path detected as device")
	}
}
