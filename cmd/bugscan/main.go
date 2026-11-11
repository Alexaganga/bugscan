package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bugscan/internal/check"
	"bugscan/internal/engine"
	"bugscan/internal/report"
)

func defaultPDFPath(u *url.URL, t time.Time) string {
	host := strings.NewReplacer(":", "-", "/", "-").Replace(u.Host)
	return filepath.Join("reports", fmt.Sprintf("bugscan-%s-%s.pdf", host, t.Format("20060102-150405")))
}

func main() {
	target := flag.String("url", "", "target URL, e.g. https://example.com")
	timeout := flag.Duration("timeout", 30*time.Second, "maximum time per check")
	asJSON := flag.Bool("json", false, "print results as JSON")
	authorized := flag.Bool("authorized", false, "confirm you own this system or have written permission to test it")
	pdfPath := flag.String("pdf", "", "where to save the PDF report (default: reports/bugscan-<host>-<time>.pdf)")
	noPDF := flag.Bool("no-pdf", false, "skip PDF report generation")
	flag.Parse()

	if *target == "" {
		flag.Usage()
		os.Exit(2)
	}
	if !*authorized {
		fmt.Fprintln(os.Stderr, "Refusing to scan: pass -authorized to confirm you own this system or have written permission to test it.")
		os.Exit(2)
	}

	u, err := url.Parse(*target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		fmt.Fprintln(os.Stderr, "invalid -url: it must look like https://example.com")
		os.Exit(2)
	}

	t := check.Target{URL: u, Client: &http.Client{Timeout: *timeout}}

	// Register new checks here.
	checks := []check.Check{
		check.Headers{},
		check.TLS{},
		check.Exposed{},
	}
	ids := make([]string, 0, len(checks))
	for _, c := range checks {
		ids = append(ids, c.ID())
	}

	started := time.Now()
	findings, errs := engine.Run(context.Background(), t, checks, *timeout)
	meta := report.Meta{
		Target:    u.String(),
		Started:   started,
		Duration:  time.Since(started),
		ChecksRun: ids,
	}

	if *asJSON {
		if err := report.JSON(os.Stdout, meta, findings, errs); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	} else {
		report.Text(os.Stdout, meta, findings, errs)
	}

	if !*noPDF {
		path := *pdfPath
		if path == "" {
			path = defaultPDFPath(u, started)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "could not create report folder:", err)
			os.Exit(2)
		}
		if err := report.PDF(path, meta, findings, errs); err != nil {
			fmt.Fprintln(os.Stderr, "could not write PDF:", err)
			os.Exit(2)
		}
		abs, _ := filepath.Abs(path)
		fmt.Fprintln(os.Stderr, "\nPDF report saved:", abs)
	}

	// Non-zero exit when something severe is found, so CI pipelines can fail the build.
	for _, f := range findings {
		if f.Severity == check.High {
			os.Exit(1)
		}
	}
}
