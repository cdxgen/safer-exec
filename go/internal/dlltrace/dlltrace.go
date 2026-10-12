// Package dlltrace reports the images (DLLs and other loadable modules) a
// Windows process tree loads, from the process and image-load events of the
// Microsoft-Windows-Kernel-Process ETW provider.
//
// The ETW session lives in session_windows.go. This file holds the part that
// does not need Windows: deciding which events belong to the traced tree and
// turning kernel object paths into Win32 paths. It is unit-tested on every
// platform.
package dlltrace

import (
	"sort"
	"strings"
)

// Kind is the type of a recorded event.
type Kind uint8

const (
	// ProcessStart is Kernel-Process event 1.
	ProcessStart Kind = iota + 1
	// ProcessStop is Kernel-Process event 2.
	ProcessStop
	// ImageLoad is Kernel-Process event 5.
	ImageLoad
)

// Event is one Kernel-Process event, reduced to what attribution needs.
type Event struct {
	Kind Kind
	// Time orders the events. Real-time ETW delivers each CPU's buffers
	// separately, so arrival order is not event order.
	Time int64
	// PID is the process the event is about: the payload's ProcessID. The
	// header's process differs for the executable and ntdll.dll of a new
	// process, which the kernel maps while its creator is running.
	PID uint32
	// ParentPID is the creating process (ProcessStart only).
	ParentPID uint32
	// Image is the process's executable (ProcessStart) or the loaded file
	// (ImageLoad), as a kernel object path.
	Image string
}

// Root identifies the process whose descendants are traced. ParentPID tells
// its start event apart from one for an unrelated process that had the same
// PID before it.
type Root struct {
	PID       uint32
	ParentPID uint32
}

// Load is an image loaded by the traced tree.
type Load struct {
	// Path is the loaded file, as a kernel object path.
	Path string
	// PID and Process identify the first process that loaded it; Process is
	// a kernel object path, or empty when its start was not recorded.
	PID     uint32
	Process string
}

// instance is one process lifetime of a PID: from just after the previous
// process with that PID stopped until this one stops.
type instance struct {
	pid     uint32
	image   string
	parent  *instance
	started bool
	root    bool
	tracked int8 // 0 undecided, 1 traced, -1 not traced
}

type loadRef struct {
	in  *instance
	idx int
}

// Attribute returns the images loaded by the descendants of root, without
// duplicates, in the order they were first loaded. The root's own loads are
// not included (it is the launcher, not the workload), nor is each
// process's own executable, nor anything loaded by a process for which skip
// returns true (its children are still traced). skip receives the process's
// executable as a kernel object path and may be nil.
//
// Events are matched to process lifetimes rather than to PIDs alone, so a PID
// that Windows reuses for an unrelated process after a traced one exits does
// not carry the trace over.
func Attribute(events []Event, root Root, skip func(processImage string) bool) []Load {
	order := make([]int, len(events))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return events[order[a]].Time < events[order[b]].Time })

	live := make(map[uint32]*instance)
	var all []*instance
	current := func(pid uint32) *instance {
		if in := live[pid]; in != nil {
			return in
		}
		in := &instance{pid: pid}
		live[pid] = in
		all = append(all, in)
		return in
	}

	var loads []loadRef
	for _, i := range order {
		e := &events[i]
		switch e.Kind {
		case ProcessStart:
			if in := live[e.PID]; in != nil && in.started {
				// A second start without a stop: the stop event was lost.
				delete(live, e.PID)
			}
			// The instance may already exist: the kernel maps a new process's
			// executable and ntdll.dll before it logs the start.
			in := current(e.PID)
			in.started = true
			in.image = e.Image
			if e.ParentPID != e.PID {
				in.parent = current(e.ParentPID)
			}
			if e.PID == root.PID && e.ParentPID == root.ParentPID {
				in.root = true
			}
		case ProcessStop:
			delete(live, e.PID)
		case ImageLoad:
			loads = append(loads, loadRef{in: current(e.PID), idx: i})
		}
	}

	// Without the root's start event (lost, or the session started late),
	// accept the lifetime of its PID that was already running.
	haveRoot := false
	for _, in := range all {
		haveRoot = haveRoot || in.root
	}
	if !haveRoot {
		for _, in := range all {
			if in.pid == root.PID && !in.started {
				in.root = true
			}
		}
	}

	var traced func(in *instance) bool
	traced = func(in *instance) bool {
		switch in.tracked {
		case 1:
			return true
		case -1:
			return false
		}
		in.tracked = -1 // breaks a cycle should the events contain one
		if in.root || (in.parent != nil && traced(in.parent)) {
			in.tracked = 1
		}
		return in.tracked == 1
	}

	seen := make(map[string]bool)
	var out []Load
	for _, l := range loads {
		in := l.in
		if in.root || !traced(in) || (skip != nil && in.image != "" && skip(in.image)) {
			continue
		}
		path := events[l.idx].Image
		if path == "" || strings.EqualFold(path, in.image) {
			continue
		}
		key := strings.ToLower(path)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Load{Path: path, PID: in.pid, Process: in.image})
	}
	return out
}

// PathMapper turns the kernel object paths ETW reports
// (\Device\HarddiskVolume3\Windows\System32\ntdll.dll) into Win32 paths
// (C:\Windows\System32\ntdll.dll).
type PathMapper struct {
	devices    []deviceDrive
	systemRoot string
}

type deviceDrive struct {
	device, drive string
}

// NewPathMapper builds a mapper from each drive letter's device (drive "C:"
// to "\Device\HarddiskVolume3", as QueryDosDevice reports it) and the Windows
// directory. Drives whose target is not a device, such as SUBST drives, are
// ignored: the kernel reports files on them under their real volume.
func NewPathMapper(drives map[string]string, systemRoot string) *PathMapper {
	m := &PathMapper{systemRoot: strings.TrimRight(systemRoot, `\`)}
	for drive, device := range drives {
		if !hasPrefixFold(device, `\Device\`) {
			continue
		}
		m.devices = append(m.devices, deviceDrive{device: strings.TrimRight(device, `\`), drive: strings.ToUpper(drive)})
	}
	sort.Slice(m.devices, func(a, b int) bool {
		if len(m.devices[a].device) != len(m.devices[b].device) {
			return len(m.devices[a].device) > len(m.devices[b].device)
		}
		return m.devices[a].drive < m.devices[b].drive
	})
	return m
}

// Win32Path returns the Win32 form of a kernel object path, or the path
// unchanged when no form is known.
func (m *PathMapper) Win32Path(p string) string {
	switch {
	case hasPrefixFold(p, `\??\UNC\`):
		return `\\` + p[len(`\??\UNC\`):]
	case hasPrefixFold(p, `\??\`):
		return p[len(`\??\`):]
	case hasPrefixFold(p, `\SystemRoot\`) && m.systemRoot != "":
		return m.systemRoot + p[len(`\SystemRoot`):]
	case hasPrefixFold(p, `\Device\Mup\`):
		return `\\` + stripRedirectorPrefix(p[len(`\Device\Mup\`):])
	case hasPrefixFold(p, `\Device\LanmanRedirector\`):
		return `\\` + stripRedirectorPrefix(p[len(`\Device\LanmanRedirector\`):])
	}
	for _, d := range m.devices {
		if len(p) > len(d.device) && p[len(d.device)] == '\\' && strings.EqualFold(p[:len(d.device)], d.device) {
			return d.drive + p[len(d.device):]
		}
	}
	return p
}

// stripRedirectorPrefix drops the ";LanmanRedirector" and ";Z:0000…"
// components a mapped network drive adds in front of server\share.
func stripRedirectorPrefix(rest string) string {
	for strings.HasPrefix(rest, ";") {
		i := strings.IndexByte(rest, '\\')
		if i < 0 {
			return rest
		}
		rest = rest[i+1:]
	}
	return rest
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}
