// Covert-channel detection — audit-only signals for runs that try to signal
// another workload without a network connection.
//
// Agents in separate sandboxes on one host can exchange data by modulating a
// shared resource: alternating bursts of disk writes and idle periods, or of
// CPU load and sleep, that the other side measures as timing differences; or
// by writing into a directory another sandbox can also write. Neither can be
// blocked without breaking ordinary builds, so the engine records them as
// audit entries instead:
//
//   - timing-channel-suspect: the run's aggregate IO or CPU usage, sampled
//     every contentionInterval, switched between near-idle and a plateau many
//     times within a short window (on/off keying) — see onOffKeying.
//   - shared-write-path / shared-lock-file: another live safer-exec run of the
//     same user can write the same path, or holds the same lock file — see
//     runRegistry.
//
// Nothing here changes what the sandboxed command may do.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// contentionInterval is the sampling period of the IO and CPU counters.
const contentionInterval = 50 * time.Millisecond

// On/off keying thresholds, applied to each window of keyingWindow samples
// (10 s at contentionInterval), stepping keyingStep samples.
const (
	keyingWindow = 200
	keyingStep   = 100
	// keyingMinTransitions is the fewest idle<->busy switches in one window.
	keyingMinTransitions = 16
	// keyingMaxMidFraction is the largest share of samples that may sit
	// between the idle and busy levels; ordinary load ramps fill that band.
	// A sender whose symbols are not aligned to the sampling interval leaves
	// one partial sample at most edges, so the bound has to allow for those.
	keyingMaxMidFraction = 0.4
	// keyingMinDuty and keyingMaxDuty bound the busy share of the window, so
	// a mostly idle poller or a mostly busy compiler does not qualify.
	keyingMinDuty = 0.15
	keyingMaxDuty = 0.85
)

// keyingResult describes the first window that looked like on/off keying.
type keyingResult struct {
	Start       int     // index of the window's first sample
	Transitions int     // idle<->busy switches in the window
	Duty        float64 // busy share of the classified samples
	Level       float64 // the busy plateau (95th percentile of the window)
}

// onOffKeying reports whether samples (per-interval deltas of one counter)
// contain a window that switches between near zero and a plateau at least
// keyingMinTransitions times with few samples in between. minActive is the
// smallest plateau worth considering, in the samples' unit, so an idle run's
// noise is never classified.
func onOffKeying(samples []float64, minActive float64) (keyingResult, bool) {
	for start := 0; start+keyingWindow <= len(samples); start += keyingStep {
		if r, ok := keyingWindowResult(samples[start:start+keyingWindow], minActive); ok {
			r.Start = start
			return r, true
		}
	}
	return keyingResult{}, false
}

func keyingWindowResult(w []float64, minActive float64) (keyingResult, bool) {
	sorted := append([]float64(nil), w...)
	sort.Float64s(sorted)
	level := sorted[len(sorted)*95/100]
	if level < minActive {
		return keyingResult{}, false
	}
	off, on := level*0.1, level*0.5
	state, transitions, busy, classified, mid := -1, 0, 0, 0, 0
	for _, v := range w {
		s := -1
		switch {
		case v <= off:
			s = 0
		case v >= on:
			s = 1
		default:
			mid++
			continue
		}
		classified++
		busy += s
		if state >= 0 && s != state {
			transitions++
		}
		state = s
	}
	if classified == 0 || float64(mid)/float64(len(w)) > keyingMaxMidFraction || transitions < keyingMinTransitions {
		return keyingResult{}, false
	}
	duty := float64(busy) / float64(classified)
	if duty < keyingMinDuty || duty > keyingMaxDuty {
		return keyingResult{}, false
	}
	return keyingResult{Transitions: transitions, Duty: duty, Level: level}, true
}

// contentionSampler polls a cumulative CPU-time and IO-byte counter for the
// whole sandbox (a cgroup on Linux, the job object on Windows) and keeps the
// per-interval deltas.
type contentionSampler struct {
	read func() (cpuUsec, ioBytes uint64, ok bool)
	stop chan struct{}
	done chan struct{}
	mu   sync.Mutex
	cpu  []float64
	io   []float64
}

// sampleCount returns how many intervals have been sampled so far.
func (s *contentionSampler) sampleCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.cpu)
}

// maxContentionSamples bounds memory to one hour of samples per counter.
const maxContentionSamples = int(time.Hour / contentionInterval)

func startContentionSampler(read func() (cpuUsec, ioBytes uint64, ok bool)) *contentionSampler {
	s := &contentionSampler{read: read, stop: make(chan struct{}), done: make(chan struct{})}
	go s.loop()
	return s
}

func (s *contentionSampler) loop() {
	defer close(s.done)
	t := time.NewTicker(contentionInterval)
	defer t.Stop()
	var lastCPU, lastIO uint64
	primed := false
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
		}
		cpu, io, ok := s.read()
		if !ok {
			continue
		}
		s.mu.Lock()
		if primed && len(s.cpu) < maxContentionSamples {
			s.cpu = append(s.cpu, float64(sub(cpu, lastCPU)))
			s.io = append(s.io, float64(sub(io, lastIO)))
		}
		s.mu.Unlock()
		lastCPU, lastIO, primed = cpu, io, true
	}
}

func sub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

// The smallest busy plateau considered: 5 ms of CPU per 50 ms interval (a
// tenth of a core) and 64 KiB of IO per interval.
const (
	keyingMinCPUUsec = 5000
	keyingMinIOBytes = 64 << 10
)

// finish stops sampling and returns a timing-channel-suspect entry for each
// counter whose samples show on/off keying.
func (s *contentionSampler) finish() []config.AuditEntry {
	if s == nil {
		return nil
	}
	close(s.stop)
	<-s.done
	var out []config.AuditEntry
	for _, c := range []struct {
		name, unit string
		samples    []float64
		min        float64
		what       string
	}{
		{"cpu", "µs of CPU", s.cpu, keyingMinCPUUsec, "CPU-time contention"},
		{"io", "bytes of IO", s.io, keyingMinIOBytes, "storage contention"},
	} {
		r, ok := onOffKeying(c.samples, c.min)
		if !ok {
			continue
		}
		at := time.Duration(r.Start) * contentionInterval
		out = append(out, config.AuditEntry{
			Type:   "timing-channel-suspect",
			Target: c.name,
			Detail: fmt.Sprintf("%d idle/busy switches within %s from %s into the run (busy %.0f%% of the time at about %.0f %s per %s); a workload alternating like this can signal another sandbox on the host through %s",
				r.Transitions, time.Duration(keyingWindow)*contentionInterval, at.Round(time.Millisecond), r.Duty*100, r.Level, c.unit, contentionInterval, c.what),
		})
	}
	return out
}

// runRecord is one live run's entry in the registry.
type runRecord struct {
	PID        int      `json:"pid"`
	Started    int64    `json:"started"`
	Command    string   `json:"command"`
	WritePaths []string `json:"writePaths,omitempty"`
	LockFiles  []string `json:"lockFiles,omitempty"`
}

// runRegistry records this run's writable paths and lock files in a per-user
// directory, so concurrent runs can find out what they share. Every run
// registers; only audited runs report.
type runRegistry struct {
	dir  string
	file string
	self runRecord
	mu   sync.Mutex
	seen map[string]bool
}

// registryDir is the per-user directory of live run records.
func registryDir() string {
	name := "safer-exec-runs"
	if uid := os.Getuid(); uid >= 0 {
		name += "-" + strconv.Itoa(uid)
	}
	return filepath.Join(os.TempDir(), name)
}

// registerRun writes this run's record. It returns nil (and the run goes
// unregistered) when the registry directory is unusable — for instance when
// it exists but is not a private directory of this user.
func registerRun(cfg config.ExecConfig) *runRegistry {
	dir := registryDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil
	}
	if !privateDir(dir) {
		return nil
	}
	r := &runRegistry{dir: dir, seen: make(map[string]bool), self: runRecord{
		PID:        os.Getpid(),
		Started:    time.Now().UnixNano(),
		Command:    filepath.Base(cfg.Cmd),
		WritePaths: cleanPaths(cfg.WritePaths),
	}}
	for _, l := range cfg.LockFiles {
		if l.Path != "" {
			r.self.LockFiles = append(r.self.LockFiles, cleanPaths([]string{l.Path})...)
		}
	}
	data, err := json.Marshal(r.self)
	if err != nil {
		return nil
	}
	r.file = filepath.Join(dir, fmt.Sprintf("%d-%d.json", r.self.PID, r.self.Started))
	if err := os.WriteFile(r.file, data, 0o600); err != nil {
		return nil
	}
	return r
}

func cleanPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			p = resolved
		}
		out = append(out, filepath.Clean(p))
	}
	return out
}

// pathsOverlap reports whether a and b are the same path or one contains the
// other. Windows and macOS file systems are case-insensitive by default.
func pathsOverlap(a, b string) bool {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		a, b = strings.ToLower(a), strings.ToLower(b)
	}
	if a == b {
		return true
	}
	within := func(child, parent string) bool {
		rel, err := filepath.Rel(parent, child)
		return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
	}
	return within(a, b) || within(b, a)
}

// check compares this run with every other live run in the registry and
// returns one entry per newly found shared path. Records of runs that are no
// longer alive are removed.
func (r *runRegistry) check() []config.AuditEntry {
	if r == nil {
		return nil
	}
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []config.AuditEntry
	for _, e := range entries {
		path := filepath.Join(r.dir, e.Name())
		if path == r.file || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var other runRecord
		if json.Unmarshal(data, &other) != nil || other.PID <= 0 {
			continue
		}
		if !pidAlive(other.PID) {
			os.Remove(path)
			continue
		}
		report := func(typ, mine, theirs, what string) {
			key := typ + "\x00" + mine + "\x00" + e.Name()
			if r.seen[key] {
				return
			}
			r.seen[key] = true
			out = append(out, config.AuditEntry{
				Type:   typ,
				Target: mine,
				Detail: fmt.Sprintf("concurrent sandbox pid %d (%s) %s %s; the two runs can pass data through it", other.PID, other.Command, what, theirs),
			})
		}
		for _, mine := range r.self.WritePaths {
			for _, theirs := range other.WritePaths {
				if pathsOverlap(mine, theirs) {
					report("shared-write-path", mine, theirs, "can also write")
				}
			}
		}
		for _, mine := range r.self.LockFiles {
			for _, theirs := range other.LockFiles {
				if pathsOverlap(mine, theirs) {
					report("shared-lock-file", mine, theirs, "also locks")
				}
			}
		}
	}
	return out
}

// close removes this run's record.
func (r *runRegistry) close() {
	if r != nil {
		os.Remove(r.file)
	}
}

// emitDetections writes detection entries as audit lines.
func emitDetections(entries []config.AuditEntry) {
	for _, e := range entries {
		data, err := json.Marshal(map[string]string{"type": e.Type, "target": e.Target, "details": e.Detail})
		if err == nil {
			emitAuditLine(data, os.Stderr)
		}
	}
}
