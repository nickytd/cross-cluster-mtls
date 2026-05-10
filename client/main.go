package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"
)

func main() {
	credsFile := os.Getenv("CREDS_BUNDLE")
	trustFile := os.Getenv("TRUST_BUNDLE")
	serverAddr := os.Getenv("SERVER_ADDR")

	if credsFile == "" || trustFile == "" || serverAddr == "" {
		slog.Error("CREDS_BUNDLE, TRUST_BUNDLE, and SERVER_ADDR must be set")
		os.Exit(1)
	}

	slog.Info("client starting", "creds", credsFile, "trust", trustFile, "server", serverAddr)

	for {
		err := doRequest(credsFile, trustFile, serverAddr)
		if err != nil {
			slog.Warn("request failed", "error", err)
		}
		time.Sleep(10 * time.Second)
	}
}

func doRequest(credsFile, trustFile, serverAddr string) error {
	credsData, err := os.ReadFile(credsFile)
	if err != nil {
		return fmt.Errorf("reading creds: %w", err)
	}

	cert, err := tls.X509KeyPair(credsData, credsData)
	if err != nil {
		return fmt.Errorf("parsing key pair: %w", err)
	}

	trustData, err := os.ReadFile(trustFile)
	if err != nil {
		return fmt.Errorf("reading trust bundle: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(trustData) {
		return fmt.Errorf("no certs in trust bundle")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   "mtls-server.server",
	}

	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   10 * time.Second,
	}

	resp, err := httpClient.Get(fmt.Sprintf("https://%s/", serverAddr))
	if err != nil {
		return fmt.Errorf("GET: %w", err)
	}
	defer resp.Body.Close()

	body := make([]byte, 1024)
	n, _ := resp.Body.Read(body)
	slog.Info("response", "status", resp.StatusCode, "body", string(body[:n]))
	return nil
}
