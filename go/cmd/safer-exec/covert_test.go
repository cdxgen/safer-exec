package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// keyed returns samples that encode bits as busy/idle symbols of symbolLen
// samples each, the way the storage covert channel in OpenAI's red-team
// report alternated continuous writes with idle periods.
func keyed(bits string, symbolLen int, level float64, jitter float64) []float64 {
	rng := rand.New(rand.NewSource(1))
	var out []float64
	for _, b := range bits {
		for i := 0; i < symbolLen; i++ {
			v := rng.Float64() * jitter * level
			if b == '1' {
				v = level * (1 - jitter*rng.Float64())
			}
			out = append(out, v)
		}
	}
	return out
}

func TestOnOffKeyingDetectsModulatedLoad(t *testing.T) {
	bits := strings.Repeat("1011001110001011", 8)
	samples := append(make([]float64, 40), keyed(bits, 2, 8<<20, 0.05)...)
	r, ok := onOffKeying(samples, keyingMinIOBytes)
	if !ok {
		t.Fatal("on/off keyed IO was not detected")
	}
	if r.Transitions < keyingMinTransitions || r.Duty < 0.3 || r.Duty > 0.7 {
		t.Fatalf("result = %+v", r)
	}
}

// integrated samples a keyed signal whose symbols last symbol, not a whole
// number of intervals, so the samples at most edges are partial — what a real
// sender looks like through a 50 ms counter.
func integrated(bits string, symbol, interval time.Duration, level float64) []float64 {
	total := time.Duration(len(bits)) * symbol
	var out []float64
	for start := time.Duration(0); start+interval <= total; start += interval {
		busy := time.Duration(0)
		for t := start; t < start+interval; t += time.Millisecond {
			if bits[int(t/symbol)] == '1' {
				busy += time.Millisecond
			}
		}
		out = append(out, level*float64(busy)/float64(interval))
	}
	return out
}

func TestOnOffKeyingDetectsUnalignedSymbols(t *testing.T) {
	for _, symbol := range []time.Duration{100 * time.Millisecond, 125 * time.Millisecond, 175 * time.Millisecond} {
		bits := strings.Repeat("1011001110001011", 8)
		samples := integrated(bits, symbol, contentionInterval, 50000)
		if r, ok := onOffKeying(samples, keyingMinCPUUsec); !ok {
			t.Errorf("symbol %s: not detected", symbol)
		} else if r.Transitions < keyingMinTransitions {
			t.Errorf("symbol %s: %+v", symbol, r)
		}
	}
}

func TestOnOffKeyingIgnoresOrdinaryLoad(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	cases := map[string][]float64{}

	// A compiler: busy throughout, with noisy load.
	var busy []float64
	for i := 0; i < 600; i++ {
		busy = append(busy, 30000+rng.Float64()*20000)
	}
	cases["steady busy"] = busy

	// A download: ramps up and down smoothly.
	var ramp []float64
	for i := 0; i < 600; i++ {
		x := float64(i%120) / 120
		ramp = append(ramp, (1-((2*x-1)*(2*x-1)))*4e6)
	}
	cases["ramps"] = ramp

	// A poller: one busy sample a second, idle otherwise.
	var poll []float64
	for i := 0; i < 600; i++ {
		v := 0.0
		if i%20 == 0 {
			v = 1e6
		}
		poll = append(poll, v)
	}
	cases["poller"] = poll

	// Noise below the activity floor.
	var idle []float64
	for i := 0; i < 600; i++ {
		v := 0.0
		if i%2 == 0 {
			v = 1000
		}
		idle = append(idle, v)
	}
	cases["idle noise"] = idle

	// Too short to judge.
	cases["short"] = keyed(strings.Repeat("10", 40), 1, 1e7, 0)

	for name, s := range cases {
		if r, ok := onOffKeying(s, keyingMinIOBytes); ok {
			t.Errorf("%s: flagged as keying: %+v", name, r)
		}
	}
}

func TestContentionSamplerReportsKeying(t *testing.T) {
	var cpu, io uint64
	step := 0
	s := startContentionSampler(func() (uint64, uint64, bool) {
		// Busy for two samples, idle for two: CPU keyed, IO flat.
		if (step/2)%2 == 0 {
			cpu += 40000
		}
		io += 100
		step++
		return cpu, io, true
	})
	deadline := time.Now().Add(20 * time.Second)
	for {
		s2 := s.sampleCount()
		if s2 >= keyingWindow+5 || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	entries := s.finish()
	if len(entries) != 1 || entries[0].Type != "timing-channel-suspect" || entries[0].Target != "cpu" {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestPathsOverlap(t *testing.T) {
	sep := string(filepath.Separator)
	a := filepath.Join(sep+"work", "cache")
	cases := []struct {
		x, y string
		want bool
	}{
		{a, a, true},
		{a, filepath.Join(a, "npm"), true},
		{filepath.Join(a, "npm"), a, true},
		{a, a + "-other", false},
		{a, filepath.Join(sep+"work", "other"), false},
	}
	for _, c := range cases {
		if got := pathsOverlap(c.x, c.y); got != c.want {
			t.Errorf("pathsOverlap(%q, %q) = %v", c.x, c.y, got)
		}
	}
}

// Two live runs that can write the same directory find each other; the
// record of a run that has exited is removed instead of reported.
func TestRunRegistryReportsSharedPaths(t *testing.T) {
	tmp := t.TempDir()
	isolateRegistry(t, tmp)
	shared := filepath.Join(tmp, "shared")
	if err := os.MkdirAll(filepath.Join(shared, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(tmp, "build.lock")

	reg := registerRun(config.ExecConfig{Cmd: "/usr/bin/npm", WritePaths: []string{shared}, LockFiles: []config.LockFileSpec{{Path: lock}}})
	if reg == nil {
		t.Fatal("registration failed")
	}
	defer reg.close()

	// A live peer (this process, under another record) and a dead one.
	writeRecord := func(name string, rec runRecord) {
		data, _ := json.Marshal(rec)
		if err := os.WriteFile(filepath.Join(reg.dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	resolvedShared := cleanPaths([]string{filepath.Join(shared, "sub")})[0]
	resolvedLock := cleanPaths([]string{lock})[0]
	dead := deadPID(t)
	writeRecord(fmt.Sprintf("%d-1.json", os.Getpid()), runRecord{PID: os.Getpid(), Started: 1, Command: "pip", WritePaths: []string{resolvedShared}, LockFiles: []string{resolvedLock}})
	writeRecord(fmt.Sprintf("%d-2.json", dead), runRecord{PID: dead, Started: 2, Command: "gone", WritePaths: []string{resolvedShared}, LockFiles: []string{resolvedLock}})

	entries := reg.check()
	types := map[string]int{}
	for _, e := range entries {
		types[e.Type]++
		if !strings.Contains(e.Detail, "pip") {
			t.Errorf("entry does not name the peer: %+v", e)
		}
	}
	if types["shared-write-path"] != 1 || types["shared-lock-file"] != 1 || len(entries) != 2 {
		t.Fatalf("entries = %+v", entries)
	}
	if _, err := os.Stat(filepath.Join(reg.dir, fmt.Sprintf("%d-2.json", dead))); !os.IsNotExist(err) {
		t.Fatal("the dead run's record was not removed")
	}
	if again := reg.check(); len(again) != 0 {
		t.Fatalf("the same overlap was reported twice: %+v", again)
	}
}

// deadPID returns the pid of a process that has already exited.
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return cmd.Process.Pid
}

// isolateRegistry points the user cache and temp directories at dir.
func isolateRegistry(t *testing.T, dir string) {
	t.Helper()
	for _, k := range []string{"TMPDIR", "TMP", "TEMP", "HOME", "XDG_CACHE_HOME", "LocalAppData", "USERPROFILE"} {
		t.Setenv(k, dir)
	}
}

// Records a workload could plant are skipped without blocking or following
// links: a FIFO, a symlink, an oversized file, and a record whose name does
// not match its content.
func TestRunRegistryIgnoresPlantedRecords(t *testing.T) {
	tmp := t.TempDir()
	isolateRegistry(t, tmp)
	shared := filepath.Join(tmp, "shared")
	os.MkdirAll(shared, 0o755)
	reg := registerRun(config.ExecConfig{Cmd: "npm", WritePaths: []string{shared}})
	if reg == nil {
		t.Fatal("registration failed")
	}
	defer reg.close()
	if !strings.HasPrefix(reg.dir, tmp) {
		t.Fatalf("registry %s is outside the isolated cache %s", reg.dir, tmp)
	}
	resolved := cleanPaths([]string{shared})
	good, _ := json.Marshal(runRecord{PID: os.Getpid(), Started: 7, Command: "forged", WritePaths: resolved})
	// Name and content disagree.
	os.WriteFile(filepath.Join(reg.dir, "1-7.json"), good, 0o600)
	// Oversized.
	os.WriteFile(filepath.Join(reg.dir, fmt.Sprintf("%d-8.json", os.Getpid())), append(good, make([]byte, maxRecordBytes)...), 0o600)
	if runtime.GOOS != "windows" {
		target := filepath.Join(tmp, "target.json")
		os.WriteFile(target, good, 0o600)
		os.Symlink(target, filepath.Join(reg.dir, fmt.Sprintf("%d-7.json", os.Getpid())))
		if err := mkfifo(filepath.Join(reg.dir, fmt.Sprintf("%d-9.json", os.Getpid()))); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan []config.AuditEntry, 1)
	go func() { done <- reg.check() }()
	select {
	case entries := <-done:
		if len(entries) != 0 {
			t.Fatalf("planted records were reported: %+v", entries)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("check blocked on a planted record")
	}
}
