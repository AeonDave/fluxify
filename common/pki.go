package common

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
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

func EnsureBasePKI(paths PKIPaths, hostnames []string, regenerate bool) error {
	_ = os.MkdirAll(paths.Dir, 0700)
	_ = os.MkdirAll(paths.ClientsDir, 0700)
	if regenerate || !FileExists(paths.CACert) {
		_ = createCA(paths.CACert, paths.CAKey)
	}
	if regenerate || !FileExists(paths.ServerCert) {
		ca, cakey, _ := loadCA(paths.CACert, paths.CAKey)
		_ = createServerCert(paths.ServerCert, paths.ServerKey, ca, cakey, hostnames)
	}
	return nil
}

func GenerateClientBundle(paths PKIPaths, clientName string) (string, error) {
	ca, cakey, _ := loadCA(paths.CACert, paths.CAKey)
	key, _ := rsa.GenerateKey(rand.Reader, 4096)
	serial, _ := randSerial()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: clientName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, ca, &key.PublicKey, cakey)
	var b bytes.Buffer
	// IMPORTANT: tls.X509KeyPair expects the first CERTIFICATE block to match the private key.
	// Therefore write the client cert first, then append the CA cert.
	_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cb, _ := os.ReadFile(paths.CACert)
	_, _ = b.Write(cb)
	_ = pem.Encode(&b, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	// Compress with gzip
	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	_, _ = zw.Write(b.Bytes())
	_ = zw.Close()

	// Encode to base64
	b64Data := base64.StdEncoding.EncodeToString(gzBuf.Bytes())

	// Write base64-encoded bundle to disk
	out := filepath.Join(paths.ClientsDir, clientName+".bundle")
	if err := os.WriteFile(out, []byte(b64Data), 0600); err != nil {
		return "", fmt.Errorf("write bundle: %w", err)
	}
	return out, nil
}

func LoadClientBundle(path string) (*tls.Config, error) {
	// Read base64-encoded gzip bundle
	b64Data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}

	// Decode base64
	gzData, err := base64.StdEncoding.DecodeString(string(b64Data))
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}

	// Decompress gzip
	zr, err := gzip.NewReader(bytes.NewReader(gzData))
	if err != nil {
		return nil, fmt.Errorf("gzip decompress: %w", err)
	}
	defer zr.Close()

	data, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("read gzip data: %w", err)
	}

	// Parse PEM bundle
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return nil, fmt.Errorf("parse key pair: %w", err)
	}
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no valid certificates in bundle")
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: cp, MinVersion: tls.VersionTLS12}, nil
}

func ServerTLSConfig(paths PKIPaths) (*tls.Config, error) {
	cb, err := os.ReadFile(paths.CACert)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(cb) {
		return nil, fmt.Errorf("no valid CA certificates found in %s", paths.CACert)
	}
	cert, err := tls.LoadX509KeyPair(paths.ServerCert, paths.ServerKey)
	if err != nil {
		return nil, fmt.Errorf("load server key pair: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: cp, MinVersion: tls.VersionTLS12}, nil
}

func DetectClientBundlePath(dir string) (string, error) {
	m, _ := filepath.Glob(filepath.Join(dir, "*.bundle"))
	if len(m) == 0 {
		return "", fmt.Errorf("no .bundle file found in %s", dir)
	}
	if len(m) > 1 {
		return "", fmt.Errorf("multiple .bundle files found in %s (found %d), specify -cert explicitly", dir, len(m))
	}
	return m[0], nil
}

func FileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func createCA(c, k string) error {
	key, _ := rsa.GenerateKey(rand.Reader, 4096)
	serial, _ := randSerial()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	return writeCertKey(c, k, der, key)
}

func createServerCert(c, k string, ca *x509.Certificate, cak *rsa.PrivateKey, h []string) error {
	serial, _ := randSerial()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// Add SANs (Subject Alternative Names)
	for _, name := range h {
		if ip := net.ParseIP(name); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, name)
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, ca, &key.PublicKey, cak)
	return writeCertKey(c, k, der, key)
}

func writeCertKey(c, k string, der []byte, key *rsa.PrivateKey) error {
	fc, _ := os.Create(c)
	_ = pem.Encode(fc, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = fc.Close()
	fk, _ := os.Create(k)
	_ = pem.Encode(fk, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	_ = fk.Close()
	return nil
}

func loadCA(c, k string) (*x509.Certificate, *rsa.PrivateKey, error) {
	cb, _ := os.ReadFile(c)
	kb, _ := os.ReadFile(k)
	bc, _ := pem.Decode(cb)
	bk, _ := pem.Decode(kb)
	crt, _ := x509.ParseCertificate(bc.Bytes)
	key, _ := x509.ParsePKCS1PrivateKey(bk.Bytes)
	return crt, key, nil
}

func randSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func sanitizeClientName(n string) (string, error) {
	return strings.TrimSpace(n), nil
}

// BundleBaseName extracts the client name from a bundle file path.
// Removes .pem or .bundle extension.
func BundleBaseName(path string) string {
	base := filepath.Base(path)
	if strings.HasSuffix(base, ".pem") {
		return strings.TrimSuffix(base, ".pem")
	}
	if strings.HasSuffix(base, ".bundle") {
		return strings.TrimSuffix(base, ".bundle")
	}
	return base
}
