package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"log"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	var templateStr, bind string
	flag.StringVar(&templateStr, "t", "https://192.168.1.1:4443/masque{?target_host,target_port}", "URI template")
	flag.StringVar(&bind, "b", "192.168.1.1:4443", "bind to (ip:port)")
	flag.Parse()

	//Parse URI Template
	template, err := uritemplate.New(templateStr)
	if err != nil {
		log.Fatalf("invalid template: %v", err)
	}

	//Configure TLS
	tlsConf, err := generateTLSConfig()
	if err != nil {
		log.Fatalf("failed to generate certificate: %v", err)
	}

	tlsConf.NextProtos = []string{"h3"}

	quicConf := &quic.Config{
		EnableDatagrams:                true,
		InitialPacketSize:              1450, // Conservative start, PMTUD will adjust
		InitialStreamReceiveWindow:     64 * 1024 * 1024 / 2,
		MaxStreamReceiveWindow:         64 * 1024 * 1024,
		InitialConnectionReceiveWindow: 128 * 1024 * 1024 / 2,
		MaxConnectionReceiveWindow:     128 * 1024 * 1024,
		KeepAlivePeriod:                10 * time.Second,
	}

	proxy := masque.Proxy{}

	// Parse template
	u, err := url.Parse(strings.ReplaceAll(templateStr, "{?target_host,target_port}", ""))
	if err != nil {
		log.Fatalf("failed to parse URI template base: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
		req, ecnConfig, err := masque.ParseProxyRequestECN(r, template)
		if err != nil {
			if perr, ok := errors.AsType[*masque.ProxyRequestParseError](err); ok {
				w.WriteHeader(perr.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		proxy.ProxyECN(w, req, ecnConfig)
	})
	server := http3.Server{
		TLSConfig:       tlsConf,
		EnableDatagrams: true,
		Logger:          slog.Default(),
		QUICConfig:      quicConf,
		Addr:            bind,
		Handler:         mux,
	}
	defer server.Close()
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("failed to run proxy: %v", err)
	}
}

// Helper to generate self-signed certs
func generateTLSConfig() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Masque Proxy"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 180),
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	kl, _ := os.OpenFile("key.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		KeyLogWriter: kl,
	}, nil
}
