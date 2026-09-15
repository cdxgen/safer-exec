// Shared dry-run report construction — used by the platform engines to turn
// captured attempted-operation events into the sorted, deduplicated DRYRUN
// payload with summary counts.
package main

import (
	"fmt"
	"sort"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// buildDryRunResult constructs a DryRunResult from collected events: events
// are sorted by type (then path/target) for predictable output, deduplicated,
// and counted into the summary. ExitCode is synthetic 0 per dry-run contract.
func buildDryRunResult(events []config.DryRunEvent, cmd string, args []string) *config.DryRunResult {
	result := &config.DryRunResult{
		ExitCode: 0,
		Events:   events,
	}
	if result.Events == nil {
		result.Events = []config.DryRunEvent{}
	}

	// Sort events by type for predictable output
	sort.Slice(result.Events, func(i, j int) bool {
		if result.Events[i].Type != result.Events[j].Type {
			return result.Events[i].Type < result.Events[j].Type
		}
		if result.Events[i].Path != result.Events[j].Path {
			return result.Events[i].Path < result.Events[j].Path
		}
		return result.Events[i].Target < result.Events[j].Target
	})

	// Deduplicate events
	seen := make(map[string]bool)
	deduped := make([]config.DryRunEvent, 0, len(result.Events))
	for _, e := range result.Events {
		key := fmt.Sprintf("%s|%s|%s|%d", e.Type, e.Path, e.Target, e.Port)
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, e)
		}
	}
	result.Events = deduped

	for _, e := range result.Events {
		switch e.Type {
		case "file-read":
			result.Summary.FileReads++
		case "file-write":
			result.Summary.FileWrites++
		case "file-metadata":
			result.Summary.FileMetadata++
		case "network-outbound":
			result.Summary.NetworkOutbound++
		case "network-bind":
			result.Summary.NetworkBind++
		case "process-exec":
			result.Summary.ExecAttempts++
		case "process-fork":
			result.Summary.ForkAttempts++
		}
	}
	result.Summary.TotalEvents = len(result.Events)

	return result
}
