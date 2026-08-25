package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/Xushengqwer/post_audit/internal/config"
)

func TestSaramaConfigAppliesRuntimeSecurityProducerAndConsumerSettings(t *testing.T) {
	tempDir := t.TempDir()
	ca := filepath.Join(tempDir, "ca.pem")
	cert := filepath.Join(tempDir, "client.pem")
	key := filepath.Join(tempDir, "client.key")
	writeTestTLSFiles(t, ca, cert, key)

	cfg, err := newSaramaConfig(config.KafkaConfig{
		Version:               "2.8.1",
		EnableSASL:            true,
		SASLUser:              "user",
		SASLPassword:          "password",
		SASLMechanism:         "SCRAM-SHA-256",
		EnableTLS:             true,
		TLSCaFile:             ca,
		TLSCertFile:           cert,
		TLSKeyFile:            key,
		TLSInsecureSkipVerify: false,
		Producer: config.ProducerConfig{
			RequiredAcks:    "wait_for_local",
			TimeoutMs:       7000,
			ReturnSuccesses: true,
			ReturnErrors:    true,
			MaxMessageBytes: 123456,
		},
		Consumer: config.ConsumerConfig{
			SessionTimeoutMs:    30000,
			HeartbeatIntervalMs: 10000,
			Offsets:             config.OffsetsConfig{AutoCommitEnable: false, Initial: "latest"},
		},
	})
	if err != nil {
		t.Fatalf("newSaramaConfig: %v", err)
	}
	if !cfg.Net.SASL.Enable || cfg.Net.SASL.User != "user" || cfg.Net.SASL.Password != "password" || cfg.Net.SASL.Mechanism != sarama.SASLTypeSCRAMSHA256 {
		t.Fatalf("SASL config not applied: %#v", cfg.Net.SASL)
	}
	if !cfg.Net.TLS.Enable || cfg.Net.TLS.Config == nil || cfg.Net.TLS.Config.InsecureSkipVerify {
		t.Fatalf("TLS config not applied safely: %#v", cfg.Net.TLS)
	}
	if cfg.Producer.RequiredAcks != sarama.WaitForLocal || cfg.Producer.Timeout != 7*time.Second || cfg.Producer.MaxMessageBytes != 123456 {
		t.Fatalf("producer config not applied: acks=%v timeout=%s max=%d", cfg.Producer.RequiredAcks, cfg.Producer.Timeout, cfg.Producer.MaxMessageBytes)
	}
	if cfg.Consumer.Group.Session.Timeout != 30*time.Second || cfg.Consumer.Group.Heartbeat.Interval != 10*time.Second || cfg.Consumer.Offsets.Initial != sarama.OffsetNewest {
		t.Fatalf("consumer config not applied: session=%s heartbeat=%s initial=%d", cfg.Consumer.Group.Session.Timeout, cfg.Consumer.Group.Heartbeat.Interval, cfg.Consumer.Offsets.Initial)
	}
}

func TestSaramaConfigRejectsUnsupportedMechanismAndUnsafeIdempotentAcks(t *testing.T) {
	if _, err := newSaramaConfig(config.KafkaConfig{Version: "2.8.1", EnableSASL: true, SASLMechanism: "OAUTHBEARER"}); err == nil {
		t.Fatalf("unsupported SASL mechanism must fail fast")
	}
	if _, err := newSaramaConfig(config.KafkaConfig{Version: "2.8.1", Producer: config.ProducerConfig{RequiredAcks: "no_response", ReturnSuccesses: true, ReturnErrors: true}}); err == nil {
		t.Fatalf("idempotent producer cannot be configured with no_response acks")
	}
}

func writeTestTLSFiles(t *testing.T, caPath, certPath, keyPath string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	files := map[string][]byte{
		caPath:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		certPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}),
		keyPath:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
	for path, body := range files {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}
