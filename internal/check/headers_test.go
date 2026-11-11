package check

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestHeadersFlagsMissingHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	findings, err := Headers{}.Run(context.Background(), Target{URL: u, Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for a response with no security headers")
	}
}
