package report

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"bugscan/internal/check"
)

func sample() []check.Finding {
	return []check.Finding{
		{CheckID: "a", Title: "Low issue", Severity: check.Low, Remediation: "Fix A"},
		{CheckID: "b", Title: "High issue", Severity: check.High, Remediation: "Fix B"},
		{CheckID: "c", Title: "Medium issue", Severity: check.Medium, Remediation: "Fix A"},
	}
}

func TestBuildPlanGroupsAndOrders(t *testing.T) {
	plan := BuildPlan(sample())
	if len(plan) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(plan))
	}
	if plan[0].Fix != "Fix B" || plan[0].Priority != "FIX NOW" {
		t.Fatalf("high severity fix should come first, got %+v", plan[0])
	}
	if plan[1].Severity != check.Medium || len(plan[1].Issues) != 2 {
		t.Fatalf("shared fix should merge issues and take the worst severity, got %+v", plan[1])
	}
}

func TestScore(t *testing.T) {
	if s, g := Score(nil); s != 100 || g != "A" {
		t.Fatalf("clean scan should be 100/A, got %d/%s", s, g)
	}
}

func TestPDFWritesFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "r.pdf")
	err := PDF(p, Meta{Target: "https://example.com", Started: time.Now(), ChecksRun: []string{"x"}}, sample(), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b, []byte("%PDF")) {
		t.Fatal("output is not a PDF")
	}
}
