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
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8443"
	}

	if credsFile == "" || trustFile == "" {
		slog.Error("CREDS_BUNDLE and TRUST_BUNDLE must be set")
		os.Exit(1)
	}

	slog.Info("server starting", "creds", credsFile, "trust", trustFile, "addr", listenAddr)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clientID := "unauthenticated"
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			clientID = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		msg := fmt.Sprintf("Hello from server! Client identity: %s\n", clientID)
		slog.Info("request", "client", clientID, "remote", r.RemoteAddr)
		w.Write([]byte(msg))
	})

	server := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				cert, clientCAs, err := loadCreds(credsFile, trustFile)
				if err != nil {
					return nil, err
				}
				return &tls.Config{
					Certificates: []tls.Certificate{cert},
					ClientCAs:    clientCAs,
					ClientAuth:   tls.RequireAndVerifyClientCert,
				}, nil
			},
		},
	}

	for {
		_, _, err := loadCreds(credsFile, trustFile)
		if err != nil {
			slog.Info("waiting for creds", "error", err)
			time.Sleep(2 * time.Second)
			continue
		}
		break
	}

	slog.Info("creds loaded, starting TLS server", "addr", listenAddr)
	if err := server.ListenAndServeTLS(credsFile, credsFile); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

func loadCreds(credsFile, trustFile string) (tls.Certificate, *x509.CertPool, error) {
	credsData, err := os.ReadFile(credsFile)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("reading creds: %w", err)
	}

	cert, err := tls.X509KeyPair(credsData, credsData)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("parsing key pair: %w", err)
	}

	trustData, err := os.ReadFile(trustFile)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("reading trust bundle: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(trustData) {
		return tls.Certificate{}, nil, fmt.Errorf("no certs in trust bundle")
	}

	return cert, pool, nil
}
