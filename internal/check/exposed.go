package check

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Exposed struct{}

func (Exposed) ID() string { return "exposed-files" }

type probe struct {
	Path  string
	Sev   Severity
	Title string
	Match func(body string) bool
}

func looksLikeHTML(b string) bool {
	return strings.Contains(strings.ToLower(b), "<html")
}

var probes = []probe{
	{"/.env", High, "Exposed .env file", func(b string) bool {
		return strings.Contains(b, "=") && !strings.Contains(b, "<") && !looksLikeHTML(b)
	}},
	{"/.git/HEAD", High, "Exposed Git repository", func(b string) bool {
		return strings.HasPrefix(strings.TrimSpace(b), "ref:")
	}},
	{"/.DS_Store", Low, "Exposed .DS_Store file", func(b string) bool {
		return strings.Contains(b, "Bud1")
	}},
	{"/phpinfo.php", Medium, "phpinfo() page exposed", func(b string) bool {
		return strings.Contains(b, "PHP Version")
	}},
	{"/server-status", Low, "Apache server-status page exposed", func(b string) bool {
		return strings.Contains(b, "Apache Server Status")
	}},
}

func (Exposed) Run(ctx context.Context, t Target) ([]Finding, error) {
	c := *t.Client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	var out []Finding
	for _, p := range probes {
		// Small delay between requests keeps the scan polite.
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}

		u := *t.URL
		u.Path = p.Path
		u.RawQuery = ""
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", UserAgent)
		resp, err := c.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK && p.Match(string(body)) {
			// Evidence deliberately excludes file contents so secrets are never copied into reports.
			out = append(out, NewFinding("exposed-files", t, p.Title, p.Sev,
				fmt.Sprintf("HTTP 200 at %s", u.String()),
				"Remove the file from the web root or block access to it in your server config."))
		}
	}
	return out, nil
}
