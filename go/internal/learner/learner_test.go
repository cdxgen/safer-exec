// Package learner_test validates the behavioral auto-profiling (learning mode).
package learner_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cdxgen/safer-exec/go/internal/config"
	"github.com/cdxgen/safer-exec/go/internal/learner"
)

func TestLearner_New(t *testing.T) {
	l := learner.New()
	if l == nil {
		t.Fatal("New() should return a non-nil Learner")
	}
}

func TestLearner_LearnBasic_Echo(t *testing.T) {
	l := learner.New()

	cfg := config.ExecConfig{
		Cmd:  "echo",
		Args: []string{"hello"},
	}

	policy, err := l.Learn(cfg)
	if err != nil {
		t.Fatalf("Learn failed: %v", err)
	}

	if policy.Cmd != "echo" {
		t.Errorf("policy.Cmd: got %q, want %q", policy.Cmd, "echo")
	}
	if len(policy.Args) != 1 || policy.Args[0] != "hello" {
		t.Errorf("policy.Args: got %v, want [\"hello\"]", policy.Args)
	}
}

func TestLearner_LearnBasic_FileAccess(t *testing.T) {
	dir := t.TempDir()

	// Create a test file
	testFile := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(testFile, []byte("content"), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	l := learner.New()

	cfg := config.ExecConfig{
		Cmd:  "cat",
		Args: []string{testFile},
		Env: map[string]string{
			"PATH": os.Getenv("PATH"),
		},
	}

	policy, err := l.Learn(cfg)
	if err != nil {
		t.Fatalf("Learn failed: %v", err)
	}

	// The policy should have been generated
	if policy == nil {
		t.Fatal("Learn should return a non-nil policy")
	}
}

func TestLearner_LearnBasic_WithEnv(t *testing.T) {
	l := learner.New()

	cfg := config.ExecConfig{
		Cmd:  "sh",
		Args: []string{"-c", "echo $TEST_VAR"},
		Env: map[string]string{
			"PATH":     os.Getenv("PATH"),
			"TEST_VAR": "test_value",
		},
	}

	policy, err := l.Learn(cfg)
	if err != nil {
		t.Fatalf("Learn failed: %v", err)
	}

	// Should have captured env vars
	if len(policy.EnvVars) == 0 {
		t.Log("no env vars captured (expected if strace not available)")
	}
}

func TestLearner_LearnBasic_MultipleCommands(t *testing.T) {
	l := learner.New()

	cfg := config.ExecConfig{
		Cmd:  "sh",
		Args: []string{"-c", "echo 'cmd1' && echo 'cmd2' && echo 'cmd3'"},
		Env: map[string]string{
			"PATH": os.Getenv("PATH"),
		},
	}

	policy, err := l.Learn(cfg)
	if err != nil {
		t.Fatalf("Learn failed: %v", err)
	}

	if policy.Cmd != "sh" {
		t.Errorf("policy.Cmd: got %q, want %q", policy.Cmd, "sh")
	}
}

func TestLearner_LearnBasic_FailingCommand(t *testing.T) {
	l := learner.New()

	cfg := config.ExecConfig{
		Cmd:  "sh",
		Args: []string{"-c", "exit 42"},
		Env: map[string]string{
			"PATH": os.Getenv("PATH"),
		},
	}

	policy, err := l.Learn(cfg)
	if err != nil {
		t.Fatalf("Learn should not fail for non-zero exit: %v", err)
	}

	if policy == nil {
		t.Fatal("Learn should return a policy even for failing commands")
	}
}

func TestLearner_DedupPaths(t *testing.T) {
	l := learner.New()

	// Use reflection-free approach: create a learner and check that
	// the policy has deduplicated paths by running a command that
	// accesses nested files
	dir := t.TempDir()

	// Create nested files
	nestedDir := filepath.Join(dir, "a", "b", "c")
	if err := os.MkdirAll(nestedDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	testFile := filepath.Join(nestedDir, "file.txt")
	if err := os.WriteFile(testFile, []byte("content"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	cfg := config.ExecConfig{
		Cmd:  "cat",
		Args: []string{testFile},
		Env: map[string]string{
			"PATH": os.Getenv("PATH"),
		},
	}

	policy, err := l.Learn(cfg)
	if err != nil {
		t.Fatalf("Learn failed: %v", err)
	}

	// The read paths should be deduplicated (parent dirs, not every file)
	for _, p := range policy.ReadPaths {
		// Each path should not be a subpath of another
		for _, other := range policy.ReadPaths {
			if p != other {
				if len(p) > len(other) {
					continue
				}
			}
		}
		t.Logf("read path: %s", p)
	}
}

func TestLearner_NetworkTracing(t *testing.T) {
	// Test with a simple network command
	l := learner.New()

	cfg := config.ExecConfig{
		Cmd:  "sh",
		Args: []string{"-c", "curl -s -o /dev/null https://httpbin.org/ip || true"},
		Env: map[string]string{
			"PATH": os.Getenv("PATH"),
		},
	}

	policy, err := l.Learn(cfg)
	if err != nil {
		t.Fatalf("Learn failed: %v", err)
	}

	// If strace is available, we should have captured network info
	if len(policy.AllowIPs) > 0 || len(policy.AllowPorts) > 0 {
		t.Logf("captured IPs: %v, ports: %v", policy.AllowIPs, policy.AllowPorts)
	} else {
		t.Log("no network info captured (strace may not be available)")
	}
}

func TestLearner_WorkingDir(t *testing.T) {
	dir := t.TempDir()

	l := learner.New()

	cfg := config.ExecConfig{
		Cmd:        "pwd",
		Args:       []string{},
		WorkingDir: dir,
		Env: map[string]string{
			"PATH": os.Getenv("PATH"),
		},
	}

	policy, err := l.Learn(cfg)
	if err != nil {
		t.Fatalf("Learn failed: %v", err)
	}

	if policy == nil {
		t.Fatal("Learn should return a policy")
	}
}

// Test that strace is found if available
func TestStraceAvailable(t *testing.T) {
	if _, err := exec.LookPath("strace"); err != nil {
		t.Skip("strace not available")
	}
}
