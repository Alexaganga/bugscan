package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"bugscan/internal/check"
)

// Run executes every check concurrently, each with its own timeout.
func Run(ctx context.Context, t check.Target, checks []check.Check, perCheck time.Duration) ([]check.Finding, []error) {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		findings []check.Finding
		errs     []error
	)
	for _, c := range checks {
		wg.Add(1)
		go func(c check.Check) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, perCheck)
			defer cancel()
			f, err := c.Run(cctx, t)

			mu.Lock()
			defer mu.Unlock()
			findings = append(findings, f...)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", c.ID(), err))
			}
		}(c)
	}
	wg.Wait()
	return findings, errs
}
