package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"bugscan/internal/check"
)

// Meta describes the scan itself.
type Meta struct {
	Target    string
	Started   time.Time
	Duration  time.Duration
	ChecksRun []string
}

func sortFindings(f []check.Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		return f[i].Severity.Rank() > f[j].Severity.Rank()
	})
}

func Text(w io.Writer, m Meta, findings []check.Finding, errs []error) {
	sortFindings(findings)
	score, grade := Score(findings)
	rule := strings.Repeat("-", 60)

	fmt.Fprintf(w, "\nScan results for %s\n%s\n", m.Target, rule)
	fmt.Fprintf(w, "Score: %d/100 (grade %s)\n\n", score, grade)

	if len(findings) == 0 {
		fmt.Fprintln(w, "No findings.")
	}
	for _, f := range findings {
		fmt.Fprintf(w, "[%s] %s\n", strings.ToUpper(string(f.Severity)), f.Title)
		if f.Evidence != "" {
			fmt.Fprintf(w, "    evidence: %s\n", f.Evidence)
		}
	}

	if plan := BuildPlan(findings); len(plan) > 0 {
		fmt.Fprintf(w, "\nWHAT TO FIX FIRST\n%s\n", rule)
		for i, a := range plan {
			fmt.Fprintf(w, "%d. [%s] %s\n", i+1, a.Priority, a.Fix)
			fmt.Fprintf(w, "     resolves: %s\n", strings.Join(a.Issues, "; "))
		}
	}
	for _, e := range errs {
		fmt.Fprintf(w, "\n[error] %v\n", e)
	}
	fmt.Fprintf(w, "\n%d finding(s) in %s\n", len(findings), m.Duration)
}

func JSON(w io.Writer, m Meta, findings []check.Finding, errs []error) error {
	sortFindings(findings)
	if findings == nil {
		findings = []check.Finding{}
	}
	score, grade := Score(findings)
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		msgs = append(msgs, e.Error())
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{
		"target":      m.Target,
		"scanned_at":  m.Started.Format(time.RFC3339),
		"duration":    m.Duration.String(),
		"score":       score,
		"grade":       grade,
		"findings":    findings,
		"action_plan": BuildPlan(findings),
		"errors":      msgs,
	})
}
