package common

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type PKIPaths struct {
	Dir        string
	CACert     string
	CAKey      string
	ServerCert string
	ServerKey  string
	ClientsDir string
}

// DefaultPKI returns default paths under the given base directory (e.g., "./pki").
func DefaultPKI(base string) PKIPaths {
	return PKIPaths{
		Dir:        base,
		CACert:     filepath.Join(base, "ca.pem"),
		CAKey:      filepath.Join(base, "ca-key.pem"),
		ServerCert: filepath.Join(base, "server.pem"),
		ServerKey:  filepath.Join(base, "server-key.pem"),
		ClientsDir: filepath.Join(base, "clients"),
	}
}

// EnsureBasePKI creates CA and server certs if missing or regenerate is true.
// hostnames is used for server SANs.
func EnsureBasePKI(paths PKIPaths, hostnames []string, regenerate bool) error {
	if err := os.MkdirAll(paths.Dir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(paths.ClientsDir, 0o700); err != nil {
		return err
	}

	needCA := regenerate || !fileExists(paths.CACert) || !fileExists(paths.CAKey)
	if needCA {
		if err := createCA(paths.CACert, paths.CAKey); err != nil {
			return fmt.Errorf("create CA: %w", err)
		}
	}

	needServer := regenerate || !fileExists(paths.ServerCert) || !fileExists(paths.ServerKey)
	if needServer {
		caCert, caKey, err := loadCA(paths.CACert, paths.CAKey)
		if err != nil {
			return fmt.Errorf("load CA: %w", err)
		}
		if err := createServerCert(paths.ServerCert, paths.ServerKey, caCert, caKey, hostnames); err != nil {
			return fmt.Errorf("create server cert: %w", err)
		}
	}
	return nil
}

// GenerateClientCert creates a client cert/key signed by CA.
func GenerateClientCert(paths PKIPaths, clientName string, regenerate bool) (certFile, keyFile string, err error) {
	cleanName, err := sanitizeClientName(clientName)
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(paths.ClientsDir, 0o700); err != nil {
		return "", "", err
	}
	certFile = filepath.Join(paths.ClientsDir, fmt.Sprintf("%s.pem", cleanName))
	keyFile = filepath.Join(paths.ClientsDir, fmt.Sprintf("%s-key.pem", cleanName))
	if !regenerate && fileExists(certFile) && fileExists(keyFile) {
		return certFile, keyFile, nil
	}
	caCert, caKey, err := loadCA(paths.CACert, paths.CAKey)
	if err != nil {
		return "", "", err
	}
	if err := createClientCert(certFile, keyFile, caCert, caKey, cleanName); err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil
}

// GenerateDatedClientCert creates a client cert/key with a timestamped filename.
// Only the dated pair is written to disk; callers can resolve the latest pair via FindLatestDatedClientCert.
func GenerateDatedClientCert(paths PKIPaths, clientName string, ts time.Time) (datedCert, datedKey, canonicalCert, canonicalKey string, err error) {
	cleanName, err := sanitizeClientName(clientName)
	if err != nil {
		return "", "", "", "", err
	}
	if ts.IsZero() {
		ts = time.Now()
	}
	if err := os.MkdirAll(paths.ClientsDir, 0o700); err != nil {
		return "", "", "", "", err
	}
	// Remove previous dated pairs for this client to keep a single cert/key.
	_ = removeDatedClientCerts(paths.ClientsDir, cleanName)

	stamp := ts.UTC().Format("20060102-150405")
	datedCert = filepath.Join(paths.ClientsDir, fmt.Sprintf("%s-%s.pem", cleanName, stamp))
	datedKey = filepath.Join(paths.ClientsDir, fmt.Sprintf("%s-%s-key.pem", cleanName, stamp))
	caCert, caKey, err := loadCA(paths.CACert, paths.CAKey)
	if err != nil {
		return "", "", "", "", err
	}
	if err := createClientCert(datedCert, datedKey, caCert, caKey, cleanName); err != nil {
		return "", "", "", "", err
	}
	// canonical paths are left empty to signal dated-only outputs
	return datedCert, datedKey, "", "", nil
}

// removeDatedClientCerts deletes existing dated cert/key pairs for a client (best effort).
func removeDatedClientCerts(dir, client string) error {
	matches, err := filepath.Glob(filepath.Join(dir, fmt.Sprintf("%s-*.pem", client)))
	if err != nil {
		return err
	}
	for _, m := range matches {
		_ = os.Remove(m)
	}
	return nil
}

// FindLatestDatedClientCert returns the newest timestamped cert/key for the given client.
// It expects files named <name>-YYYYMMDD-HHMMSS.pem and corresponding -key.pem.
func FindLatestDatedClientCert(paths PKIPaths, clientName string) (certFile, keyFile string, err error) {
	cleanName, err := sanitizeClientName(clientName)
	if err != nil {
		return "", "", err
	}
	pattern := fmt.Sprintf("%s-*.pem", cleanName)
	matches, err := filepath.Glob(filepath.Join(paths.ClientsDir, pattern))
	if err != nil {
		return "", "", err
	}
	type pair struct {
		cert string
		key  string
		ts   time.Time
	}
	pairs := make([]pair, 0)
	for _, cert := range matches {
		if strings.HasSuffix(cert, "-key.pem") {
			continue
		}
		base := filepath.Base(cert)
		if !strings.HasPrefix(base, cleanName+"-") {
			continue
		}
		stamp := strings.TrimPrefix(base, cleanName+"-")
		stamp = strings.TrimSuffix(stamp, ".pem")
		ts, parseErr := time.Parse("20060102-150405", stamp)
		if parseErr != nil {
			continue
		}
		key := strings.TrimSuffix(cert, ".pem") + "-key.pem"
		if !fileExists(key) {
			if k, splitErr := splitClientBundle(cert); splitErr == nil {
				key = k
			} else {
				continue
			}
		}
		pairs = append(pairs, pair{cert: cert, key: key, ts: ts})
	}
	if len(pairs) == 0 {
		return "", "", fmt.Errorf("no dated certs for %s", cleanName)
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].ts.After(pairs[j].ts) })
	return pairs[0].cert, pairs[0].key, nil
}

// ResolveClientCertKey returns the best client cert/key pair, splitting combined bundles when necessary.
// Prefers the latest dated cert; falls back to canonical filenames under ClientsDir.
func ResolveClientCertKey(paths PKIPaths, clientName string) (certFile, keyFile string, err error) {
	cleanName, err := sanitizeClientName(clientName)
	if err != nil {
		return "", "", err
	}
	if c, k, err := FindLatestDatedClientCert(paths, cleanName); err == nil {
		return c, k, nil
	}
	certPath := filepath.Join(paths.ClientsDir, fmt.Sprintf("%s.pem", cleanName))
	keyPath := filepath.Join(paths.ClientsDir, fmt.Sprintf("%s-key.pem", cleanName))
	if !fileExists(certPath) {
		return "", "", fmt.Errorf("client cert not found for %s", cleanName)
	}
	if !fileExists(keyPath) {
		k, splitErr := splitClientBundle(certPath)
		if splitErr != nil {
			return "", "", fmt.Errorf("client key missing for %s: %w", cleanName, splitErr)
		}
		keyPath = k
	}
	return certPath, keyPath, nil
}

var clientNameRe = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

func sanitizeClientName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("client name required")
	}
	cleaned := clientNameRe.ReplaceAllString(name, "_")
	cleaned = strings.Trim(cleaned, "-_ ")
	if cleaned == "" {
		return "", fmt.Errorf("client name invalid")
	}
	return cleaned, nil
}

// ServerTLSConfig builds a TLS config requiring client certs signed by the CA.
func ServerTLSConfig(paths PKIPaths) (*tls.Config, error) {
	caPool, err := loadCAPool(paths.CACert)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(paths.ServerCert, paths.ServerKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// ClientTLSConfig builds a TLS config with mutual auth using provided cert/key and CA.
func ClientTLSConfig(paths PKIPaths, certFile, keyFile string) (*tls.Config, error) {
	caPool, err := loadCAPool(paths.CACert)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// ---------- helpers ----------

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// splitClientBundle extracts a private key from a combined cert+key PEM file.
// It rewrites the cert file to contain only certificate blocks and writes the key to the derived -key.pem path.
func splitClientBundle(certPath string) (keyPath string, err error) {
	b, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	var certPEMs [][]byte
	var keyBlock *pem.Block
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "CERTIFICATE":
			certPEMs = append(certPEMs, pem.EncodeToMemory(blk))
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			if keyBlock == nil {
				keyBlock = blk
			}
		}
	}
	if keyBlock == nil || len(certPEMs) == 0 {
		return "", fmt.Errorf("combined cert/key not found in %s", certPath)
	}
	if err := os.WriteFile(certPath, bytes.Join(certPEMs, []byte{}), 0o644); err != nil {
		return "", err
	}
	keyPath = strings.TrimSuffix(certPath, ".pem") + "-key.pem"
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(keyBlock), 0o600); err != nil {
		return "", err
	}
	return keyPath, nil
}

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func createCA(certFile, keyFile string) error {
	serial, _ := randSerial()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "fluxify-CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := writeCertKey(certFile, keyFile, der, key); err != nil {
		return err
	}
	return nil
}

func createServerCert(certFile, keyFile string, caCert *x509.Certificate, caKey *rsa.PrivateKey, hosts []string) error {
	serial, _ := randSerial()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "fluxify-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	return writeCertKey(certFile, keyFile, der, key)
}

func createClientCert(certFile, keyFile string, caCert *x509.Certificate, caKey *rsa.PrivateKey, name string) error {
	serial, _ := randSerial()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	return writeCertKey(certFile, keyFile, der, key)
}

func writeCertKey(certFile, keyFile string, der []byte, key *rsa.PrivateKey) error {
	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer func(certOut *os.File) {
		_ = certOut.Close()
	}(certOut)
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return err
	}
	keyOut, err := os.OpenFile(keyFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func(keyOut *os.File) {
		_ = keyOut.Close()
	}(keyOut)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return err
	}
	return nil
}

func loadCA(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("invalid ca cert")
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("invalid ca key")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func loadCAPool(caFile string) (*x509.CertPool, error) {
	b, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("failed to append CA")
	}
	return pool, nil
}
