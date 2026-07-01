package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// signerName is the single signer this controller handles.
//
// The PodCertificateRequest API has no requester-side field for declaring
// intended key usage. Rather than splitting into multiple signer names, this
// controller uses one signer and lets pods opt into a serving role via the
// ekuAnnotation, which kubelet copies verbatim from
// podCertificate.userAnnotations into spec.unverifiedUserAnnotations.
const (
	signerName    = "sample.io/signer"
	ekuAnnotation = "sample.io/eku"

	ekuClient  = "client"  // default when the annotation is absent or empty
	ekuServing = "serving" // serving cert with DNS SAN
	ekuBoth    = "both"    // client + serving in one cert
)

// ekuTable maps supported annotation values to their EKU sets. Kept as data so
// resolveEKU, the deny message, and any docs pull from one source of truth.
var ekuTable = map[string][]x509.ExtKeyUsage{
	ekuClient:  {x509.ExtKeyUsageClientAuth},
	ekuServing: {x509.ExtKeyUsageServerAuth},
	ekuBoth:    {x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
}

// signer bundles the CA material and the pre-computed CA PEM used for the
// issued chain, so signPCR does not re-encode the same immutable CA on every
// request.
type signer struct {
	caKey     *ecdsa.PrivateKey
	caCert    *x509.Certificate
	caCertPEM []byte
}

func main() {
	caKeyFile := os.Getenv("CA_KEY_FILE")
	caCertFile := os.Getenv("CA_CERT_FILE")
	if caKeyFile == "" || caCertFile == "" {
		slog.Error("CA_KEY_FILE and CA_CERT_FILE must be set")
		os.Exit(1)
	}

	caKey, caCert, err := loadCA(caKeyFile, caCertFile)
	if err != nil {
		slog.Error("loading CA", "error", err)
		os.Exit(1)
	}
	slog.Info("loaded CA", "subject", caCert.Subject)

	s := &signer{
		caKey:     caKey,
		caCert:    caCert,
		caCertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}),
	}

	config, err := buildConfig()
	if err != nil {
		slog.Error("building kubeconfig", "error", err)
		os.Exit(1)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		slog.Error("creating client", "error", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	slog.Info("signer controller started", "signer", signerName)
	s.watchAndSign(ctx, client)
}

func buildConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err == nil {
		return config, nil
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = os.Getenv("HOME") + "/.kube/config"
	}
	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

func loadCA(keyFile, certFile string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("reading key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block in key file")
	}
	rawKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		rawKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing key: %w", err)
		}
	}
	ecKey, ok := rawKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("key is not ECDSA")
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("reading cert: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("no PEM block in cert file")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing cert: %w", err)
	}

	return ecKey, cert, nil
}

// Raw watch is sufficient for illustration purposes; production signers should use a proper controller framework with work queues and retries.
func (s *signer) watchAndSign(ctx context.Context, client kubernetes.Interface) {
	for {
		if err := s.doWatch(ctx, client); err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("watch error, retrying", "error", err, "retryIn", "5s")
			time.Sleep(5 * time.Second)
		}
	}
}

func (s *signer) doWatch(ctx context.Context, client kubernetes.Interface) error {
	// Field selector narrows the watch to PCRs for this signer so events for
	// other signers on the same cluster are filtered by the apiserver instead
	// of being decoded and dropped by the loop below.
	opts := metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.signerName", signerName).String(),
	}
	watcher, err := client.CertificatesV1beta1().PodCertificateRequests("").Watch(ctx, opts)
	if err != nil {
		return fmt.Errorf("starting watch: %w", err)
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return fmt.Errorf("watch channel closed")
			}
			if event.Type != watch.Added && event.Type != watch.Modified {
				continue
			}
			pcr, ok := event.Object.(*certificatesv1beta1.PodCertificateRequest)
			if !ok {
				continue
			}
			// Defensive check: with the field selector above the apiserver
			// should never send us the wrong signer, but if the selector was
			// silently dropped (e.g. downgraded apiserver) this keeps us from
			// signing PCRs we don't own.
			if pcr.Spec.SignerName != signerName {
				continue
			}
			if hasTerminalCondition(pcr) {
				continue
			}
			if err := s.signPCR(ctx, client, pcr); err != nil {
				slog.Error("signing failed", "namespace", pcr.Namespace, "name", pcr.Name, "error", err)
			}
		}
	}
}

func hasTerminalCondition(pcr *certificatesv1beta1.PodCertificateRequest) bool {
	for _, c := range pcr.Status.Conditions {
		switch c.Type {
		case certificatesv1beta1.PodCertificateRequestConditionTypeIssued,
			certificatesv1beta1.PodCertificateRequestConditionTypeDenied,
			certificatesv1beta1.PodCertificateRequestConditionTypeFailed:
			return true
		}
	}
	return false
}

// resolveEKU maps spec.unverifiedUserAnnotations to an EKU set.
//
// The client EKU is the safe default: absent OR empty annotation both resolve
// to clientAuth so templating that renders an empty value does not wedge the
// pod. Serving certs must opt in explicitly. Any other value, or any
// unrecognized domain-prefixed key, is denied — the API guidance for signers
// is "deny requests that contain keys they do not recognize."
func resolveEKU(annotations map[string]string) ([]x509.ExtKeyUsage, error) {
	for k := range annotations {
		if k != ekuAnnotation {
			return nil, fmt.Errorf("unsupported annotation key %q (only %q is recognized)", k, ekuAnnotation)
		}
	}
	value := annotations[ekuAnnotation]
	if value == "" {
		value = ekuClient
	}
	eku, ok := ekuTable[value]
	if !ok {
		return nil, fmt.Errorf("unsupported %s=%q (want %q, %q, or %q; delete the pod to retry with a corrected annotation)",
			ekuAnnotation, value, ekuClient, ekuServing, ekuBoth)
	}
	return eku, nil
}

func (s *signer) signPCR(ctx context.Context, client kubernetes.Interface, pcr *certificatesv1beta1.PodCertificateRequest) error {
	eku, err := resolveEKU(pcr.Spec.UnverifiedUserAnnotations)
	if err != nil {
		return setDenied(ctx, client, pcr, err.Error())
	}
	withDNSSAN := slices.Contains(eku, x509.ExtKeyUsageServerAuth)

	pubKey, err := x509.ParsePKIXPublicKey(pcr.Spec.PKIXPublicKey)
	if err != nil {
		return setDenied(ctx, client, pcr, fmt.Sprintf("bad public key: %v", err))
	}

	lifetime := 24 * time.Hour
	if pcr.Spec.MaxExpirationSeconds != nil && *pcr.Spec.MaxExpirationSeconds > 0 {
		requested := time.Duration(*pcr.Spec.MaxExpirationSeconds) * time.Second
		if requested < lifetime {
			lifetime = requested
		}
	}

	now := time.Now()
	notBefore := now
	notAfter := now.Add(lifetime)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generating serial: %w", err)
	}

	dnsName := fmt.Sprintf("%s.%s", pcr.Spec.PodName, pcr.Namespace)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   dnsName,
			Organization: []string{"sample.io"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
	}
	if withDNSSAN {
		template.DNSNames = []string{dnsName}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, s.caCert, pubKey, s.caKey)
	if err != nil {
		return fmt.Errorf("creating certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	chain := string(certPEM) + string(s.caCertPEM)

	ekuLabel := annotationValue(pcr.Spec.UnverifiedUserAnnotations)

	pcr.Status.CertificateChain = chain
	pcr.Status.NotBefore = new(metav1.NewTime(notBefore))
	pcr.Status.NotAfter = new(metav1.NewTime(notAfter))
	pcr.Status.BeginRefreshAt = new(metav1.NewTime(now.Add(lifetime * 2 / 3)))
	pcr.Status.Conditions = append(pcr.Status.Conditions, metav1.Condition{
		Type:               certificatesv1beta1.PodCertificateRequestConditionTypeIssued,
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             "Signed",
		Message:            fmt.Sprintf("Certificate issued (eku=%s)", ekuLabel),
	})

	_, err = client.CertificatesV1beta1().PodCertificateRequests(pcr.Namespace).UpdateStatus(ctx, pcr, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("updating status: %w", err)
	}

	slog.Info("issued certificate",
		"namespace", pcr.Namespace,
		"name", pcr.Name,
		"pod", pcr.Spec.PodName,
		"eku", ekuLabel,
		"expires", notAfter.Format(time.RFC3339),
	)
	return nil
}

// annotationValue returns the user-facing eku value (defaulting to client)
// used in log fields and condition messages.
func annotationValue(annotations map[string]string) string {
	if v := annotations[ekuAnnotation]; v != "" {
		return v
	}
	return ekuClient
}

func setDenied(ctx context.Context, client kubernetes.Interface, pcr *certificatesv1beta1.PodCertificateRequest, reason string) error {
	pcr.Status.Conditions = append(pcr.Status.Conditions, metav1.Condition{
		Type:               certificatesv1beta1.PodCertificateRequestConditionTypeDenied,
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             "InvalidRequest",
		Message:            reason,
	})
	_, err := client.CertificatesV1beta1().PodCertificateRequests(pcr.Namespace).UpdateStatus(ctx, pcr, metav1.UpdateOptions{})
	return err
}
