package check

import (
	"context"
	"io"
	"net/http"
	"strings"
)

type Headers struct{}

func (Headers) ID() string { return "security-headers" }

func (Headers) Run(ctx context.Context, t Target) ([]Finding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := t.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	h := resp.Header
	var out []Finding
	add := func(title string, sev Severity, evidence, fix string) {
		out = append(out, NewFinding("security-headers", t, title, sev, evidence, fix))
	}

	if t.URL.Scheme == "https" && h.Get("Strict-Transport-Security") == "" {
		add("Missing Strict-Transport-Security header", Medium, "header not present",
			"Add: Strict-Transport-Security: max-age=31536000; includeSubDomains")
	}
	if h.Get("X-Content-Type-Options") == "" {
		add("Missing X-Content-Type-Options header", Low, "header not present",
			"Add: X-Content-Type-Options: nosniff")
	}
	csp := h.Get("Content-Security-Policy")
	if csp == "" {
		add("Missing Content-Security-Policy header", Low, "header not present",
			"Define a Content-Security-Policy that restricts script and frame sources.")
	}
	if h.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		add("Page may be framed (clickjacking)", Low, "no X-Frame-Options or CSP frame-ancestors",
			"Add X-Frame-Options: DENY or a CSP frame-ancestors directive.")
	}
	if h.Get("Referrer-Policy") == "" {
		add("Missing Referrer-Policy header", Info, "header not present",
			"Add: Referrer-Policy: strict-origin-when-cross-origin")
	}
	if v := h.Get("Server"); strings.ContainsAny(v, "0123456789") {
		add("Server header discloses version", Info, "Server: "+v,
			"Hide version details in your web server configuration.")
	}
	return out, nil
}
