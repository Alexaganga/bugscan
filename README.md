# bugscan

A passive web security scanner. Only scan systems you own or have written permission to test.

## Usage
    go build -o bin/bugscan ./cmd/bugscan
    ./bin/bugscan -url https://your-site.com -authorized
    ./bin/bugscan -url https://your-site.com -authorized -json
    ./bin/bugscan -url https://your-site.com -authorized -pdf ~/Documents/report.pdf
    ./bin/bugscan -url https://your-site.com -authorized -no-pdf

## PDF report
Every scan writes a PDF to `reports/` with a score, a prioritised "What to fix first" plan,
and detailed findings.

## Layout
- cmd/bugscan        CLI entrypoint
- internal/check     check interface plus the checks (headers, tls, exposed files)
- internal/engine    runs checks concurrently
- internal/report    text, JSON and PDF output, action plan and score

## Adding a check
Create a type in internal/check that implements `Check`, then register it in cmd/bugscan/main.go.

## Roadmap
API server, PostgreSQL storage, Next.js dashboard, scheduled scans, ownership verification, YAML check templates.
