package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/quic-go/masque-go"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	var templateStr, bind, keyFile, certFile string
	//flag.StringVar(&templateStr, "t", "", "URI template")
	//flag.StringVar(&bind, "b", "", "bind to (ip:port)")
	//flag.StringVar(&keyFile, "k", "", "key file")
	//flag.StringVar(&certFile, "c", "", "cert file")
	//flag.Parse()
	templateStr = "https://localhost:4433/masque{?target_host,target_port}"
	bind = "localhost:4433"
	keyFile = "./key.pem"
	certFile = "./cert.pem"

	if templateStr == "" || bind == "" || keyFile == "" || certFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Parse the template definition for use inside the handler
	template, err := uritemplate.New(templateStr)
	if err != nil {
		log.Fatalf("invalid template: %v", err)
	}

	// Load TLS certs
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load certificate: %v", err)
	}

	// Configure QUIC/HTTP3 Server
	tlsConf := http3.ConfigureTLSConfig(&tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	server := http3.Server{
		Addr:            bind,
		TLSConfig:       tlsConf,
		EnableDatagrams: true, // Crucial for MASQUE
		Logger:          slog.Default(),
		QUICConfig: &quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1500,
		},
	}
	defer server.Close()

	proxy := masque.Proxy{}

	// Parse the template URL to extract the base path for the HTTP handler
	u, err := url.Parse(templateStr)
	if err != nil {
		log.Fatalf("failed to parse URI template: %v", err)
	}

	// FIX: Go 1.22+ treats '{' as a wildcard in routes.
	// We must strip the template variables from the path before registering.
	handlerPath := u.Path
	if idx := strings.Index(handlerPath, "{"); idx != -1 {
		handlerPath = handlerPath[:idx]
	}

	log.Printf("Listening on %s", bind)
	log.Printf("Handling MASQUE requests at path: %s", handlerPath)

	http.HandleFunc(handlerPath, func(w http.ResponseWriter, r *http.Request) {
		// masque.ParseRequest uses the full template to validate the request
		req, ecnConfig, err := masque.ParseRequest(r, template)
		if err != nil {
			var perr *masque.RequestParseError
			if errors.As(err, &perr) {
				w.WriteHeader(perr.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		proxy.Proxy(w, req, ecnConfig)
	})

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("failed to run proxy: %v", err)
	}
}
