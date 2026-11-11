package report

import (
	"sort"

	"bugscan/internal/check"
)

// Action is one recommended fix. Findings that share the same fix are merged,
// so the reader gets a short to-do list instead of a wall of issues.
type Action struct {
	Priority string         `json:"priority"`
	Severity check.Severity `json:"severity"`
	Fix      string         `json:"fix"`
	Issues   []string       `json:"resolves"`
}

func priorityLabel(s check.Severity) string {
	switch s {
	case check.High:
		return "FIX NOW"
	case check.Medium:
		return "FIX THIS WEEK"
	case check.Low:
		return "FIX SOON"
	}
	return "HARDENING"
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// BuildPlan groups findings by remediation and orders the result worst-first.
func BuildPlan(findings []check.Finding) []Action {
	byFix := map[string]*Action{}
	var order []string
	for _, f := range findings {
		fix := f.Remediation
		if fix == "" {
			fix = "Review and resolve: " + f.Title
		}
		a, ok := byFix[fix]
		if !ok {
			a = &Action{Fix: fix, Severity: f.Severity}
			byFix[fix] = a
			order = append(order, fix)
		}
		if f.Severity.Rank() > a.Severity.Rank() {
			a.Severity = f.Severity
		}
		if !contains(a.Issues, f.Title) {
			a.Issues = append(a.Issues, f.Title)
		}
	}
	plan := make([]Action, 0, len(order))
	for _, k := range order {
		a := byFix[k]
		a.Priority = priorityLabel(a.Severity)
		plan = append(plan, *a)
	}
	sort.SliceStable(plan, func(i, j int) bool {
		return plan[i].Severity.Rank() > plan[j].Severity.Rank()
	})
	return plan
}

// Score is a simple heuristic: start at 100 and subtract per finding.
// It only reflects what this passive scan checked, not overall security.
func Score(findings []check.Finding) (int, string) {
	score := 100
	for _, f := range findings {
		switch f.Severity {
		case check.High:
			score -= 25
		case check.Medium:
			score -= 10
		case check.Low:
			score -= 3
		default:
			score -= 1
		}
	}
	if score < 0 {
		score = 0
	}
	grade := "F"
	switch {
	case score >= 90:
		grade = "A"
	case score >= 75:
		grade = "B"
	case score >= 60:
		grade = "C"
	case score >= 40:
		grade = "D"
	}
	return score, grade
}

func Counts(findings []check.Finding) map[check.Severity]int {
	m := map[check.Severity]int{}
	for _, f := range findings {
		m[f.Severity]++
	}
	return m
}
