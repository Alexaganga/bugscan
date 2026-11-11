package check

import (
	"context"
	"net/http"
	"net/url"
)

const UserAgent = "bugscan/0.1 (authorized security testing)"

type Severity string

const (
	Info   Severity = "info"
	Low    Severity = "low"
	Medium Severity = "medium"
	High   Severity = "high"
)

// Rank orders severities so reports can sort worst-first.
func (s Severity) Rank() int {
	switch s {
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	}
	return 0
}

type Finding struct {
	CheckID     string   `json:"check_id"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Target      string   `json:"target"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

type Target struct {
	URL    *url.URL
	Client *http.Client
}

// Check is the plugin interface. Add a new check by implementing it
// and registering it in cmd/bugscan/main.go.
type Check interface {
	ID() string
	Run(ctx context.Context, t Target) ([]Finding, error)
}

func NewFinding(id string, t Target, title string, sev Severity, evidence, fix string) Finding {
	return Finding{
		CheckID:     id,
		Title:       title,
		Severity:    sev,
		Target:      t.URL.String(),
		Evidence:    evidence,
		Remediation: fix,
	}
}
