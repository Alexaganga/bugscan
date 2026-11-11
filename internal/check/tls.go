package check

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

type TLS struct{}

func (TLS) ID() string { return "tls" }

func (TLS) Run(ctx context.Context, t Target) ([]Finding, error) {
	if t.URL.Scheme != "https" {
		return []Finding{NewFinding("tls", t, "Site is not served over HTTPS", Medium,
			"scheme is "+t.URL.Scheme, "Serve the site over HTTPS and redirect HTTP to HTTPS.")}, nil
	}
	host := t.URL.Hostname()
	port := t.URL.Port()
	if port == "" {
		port = "443"
	}
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		// The certificate is inspected manually below, so handshake verification is skipped.
		Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS10, InsecureSkipVerify: true},
	}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	defer raw.Close()

	state := raw.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("server presented no certificate")
	}
	leaf := state.PeerCertificates[0]

	var out []Finding
	add := func(title string, sev Severity, evidence, fix string) {
		out = append(out, NewFinding("tls", t, title, sev, evidence, fix))
	}

	if state.Version < tls.VersionTLS12 {
		add("Outdated TLS version negotiated", High, "negotiated "+tls.VersionName(state.Version),
			"Disable TLS 1.0/1.1 and enable TLS 1.2 or newer.")
	}

	now := time.Now()
	if now.After(leaf.NotAfter) {
		add("TLS certificate has expired", High, "expired on "+leaf.NotAfter.Format("2006-01-02"),
			"Renew the certificate.")
		return out, nil
	}

	inter := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter}); err != nil {
		add("TLS certificate failed validation", High, err.Error(),
			"Install a certificate from a trusted CA that matches the hostname and includes the full chain.")
	}
	if days := int(leaf.NotAfter.Sub(now).Hours() / 24); days < 30 {
		add("TLS certificate expires soon", Medium, fmt.Sprintf("%d days remaining", days),
			"Renew the certificate and automate renewal (for example with ACME).")
	}
	return out, nil
}
