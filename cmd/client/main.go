package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/spf13/pflag"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	var proxyURITemplate string
	var ecnCMD string
	var numStreams int

	pflag.StringVarP(&proxyURITemplate, "template", "t", "", "URI template")
	pflag.StringVarP(&ecnCMD, "ecn", "e", "{false,0,0,0}", "ECN config: {enabled ,ect0 ,ect1 ,ce}")
	pflag.IntVarP(&numStreams, "streams", "n", 4, "Number of concurrent streams") // Added flag
	pflag.Lookup("ecn").NoOptDefVal = "{true,2,4,6}"

	pflag.Parse()
	if proxyURITemplate == "" {
		pflag.Usage()
		os.Exit(1)
	}
	urls := pflag.Args()
	if len(urls) != 1 {
		log.Fatal("usage: client -t <template> <url>")
	}

	ecnConfig, err := parseECNString(ecnCMD)
	if err != nil {
		log.Fatalf("Invalid ECN format: %v", err)
	}

	kl, _ := os.OpenFile("key.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)

	quicConfig := &quic.Config{
		EnableDatagrams:            true,
		InitialPacketSize:          1500,
		MaxStreamReceiveWindow:     10 * 1024 * 1024,
		MaxConnectionReceiveWindow: 50 * 1024 * 1024,
	}
	cl := masque.Client{
		QUICConfig: quicConfig,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
			KeyLogWriter:       kl,
		},
	}
	host, port, err := extractHostAndPort(urls[0])
	if err != nil {
		log.Fatalf("failed to parse url: %v", err)
	}

	var qConn *quic.Conn

	hcl := &http.Client{
		Transport: &http3.Transport{
			DisableCompression: true,
			Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
				raddr, err := net.ResolveUDPAddr("udp", host+":"+strconv.Itoa(int(port)))
				if err != nil {
					return nil, err
				}

				pconn, _, err := cl.DialECN(context.Background(), uritemplate.MustNew(proxyURITemplate), raddr, ecnConfig)
				if err != nil {
					log.Fatal("dialing MASQUE failed:", err)
				}
				log.Printf("Dialed MASQUE tunnel: %s <-> %s", pconn.LocalAddr(), raddr)

				quicConf = quicConf.Clone()
				quicConf.InitialPacketSize = 1400
				quicConf.DisablePathMTUDiscovery = false

				quicConf.MaxStreamReceiveWindow = quicConfig.MaxStreamReceiveWindow
				quicConf.MaxConnectionReceiveWindow = quicConfig.MaxConnectionReceiveWindow

				tlsConf.InsecureSkipVerify = true
				tlsConf.KeyLogWriter = kl

				conn, err := quic.DialEarly(ctx, pconn, raddr, tlsConf, quicConf)
				if err == nil {
					if qConn == nil {
						qConn = conn
					}
				}
				return conn, err
			},
		},
	}

	targetURL := urls[0]
	startTime := time.Now()
	var totalBytes int64

	req, err := http.NewRequest("HEAD", targetURL, nil)
	if err != nil {
		log.Fatalf("failed to create HEAD request: %v", err)
	}
	resp, err := hcl.Do(req)
	if err != nil {
		log.Fatalf("HEAD request failed: %v", err)
	}
	resp.Body.Close()

	contentLen := resp.ContentLength
	log.Printf("File size: %d bytes. Using %d streams.", contentLen, numStreams)

	if contentLen <= 0 || numStreams <= 1 {
		totalBytes = downloadRange(hcl, targetURL, "", 0)
	} else {
		// Parallel download using Range requests
		var wg sync.WaitGroup
		partSize := contentLen / int64(numStreams)

		for i := 0; i < numStreams; i++ {
			wg.Add(1)
			start := int64(i) * partSize
			end := start + partSize - 1
			if i == numStreams-1 {
				end = contentLen - 1
			}

			rangeHeader := fmt.Sprintf("bytes=%d-%d", start, end)

			go func(rHeader string, id int) {
				defer wg.Done()
				n := downloadRange(hcl, targetURL, rHeader, id)
				atomic.AddInt64(&totalBytes, n)
			}(rangeHeader, i)
		}
		wg.Wait()
	}

	endTime := time.Now()
	elapsed := endTime.Sub(startTime)

	throughputBps := float64(totalBytes) / elapsed.Seconds()
	throughputMbps := throughputBps * 8.0 / 1e6

	// Result Logging
	logEntry := map[string]interface{}{
		"duration":        elapsed.Seconds(),
		"bytes":           totalBytes,
		"throughput_mbps": throughputMbps,
		"streams":         numStreams,
		"ecn":             ecnConfig.Enabled,
	}

	jsonB, err := json.Marshal(logEntry)
	if err != nil {
		log.Printf("failed to marshal json log: %v", err)
	} else {
		fmt.Println(string(jsonB))
		writeLogFile(jsonB)
	}

	if qConn != nil {
		_ = qConn.CloseWithError(0, "normal closure")
	}
}

// Uning Range of Http
func downloadRange(client *http.Client, urlStr, rangeHeader string, id int) int64 {
	req, _ := http.NewRequest("GET", urlStr, nil)
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}
	rsp, err := client.Do(req)
	if err != nil {
		log.Printf("Stream %d request failed: %v", id, err)
		return 0
	}
	defer rsp.Body.Close()

	if rsp.StatusCode != http.StatusOK && rsp.StatusCode != http.StatusPartialContent {
		log.Printf("Stream %d unexpected status: %d", id, rsp.StatusCode)
		return 0
	}

	// Read into discard
	n, err := io.Copy(io.Discard, rsp.Body)
	if err != nil {
		log.Printf("Stream %d read failed: %v", id, err)
	}
	return n
}

func writeLogFile(data []byte) {
	if err := os.MkdirAll("logs", 0755); err != nil {
		log.Printf("failed to create logs directory: %v", err)
		return
	}
	fname := fmt.Sprintf("logs/transfer-%s.log", time.Now().Format("20060102-150405"))
	f, err := os.Create(fname)
	if err != nil {
		log.Printf("failed to create log file %s: %v", fname, err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		log.Printf("failed to write json log to file: %v", err)
	}
}

func extractHostAndPort(template string) (string, uint16, error) {
	u, err := url.Parse(template)
	if err != nil {
		return "", 0, err
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil || portStr == "" {
		return u.Host, 443, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("failed to parse port: %w", err)
	}
	return host, uint16(port), nil
}

func parseECNString(input string) (masque.ECNState, error) {
	var enabled bool
	var ect0, ect1, ce uint64
	_, err := fmt.Sscanf(input, "{%t,%d,%d,%d}", &enabled, &ect0, &ect1, &ce)
	if err != nil {
		return masque.ECNState{}, err
	}
	return masque.ECNState{
		Enabled:       enabled,
		ContextIdECT0: ect0,
		ContextIdECT1: ect1,
		ContextIdCE:   ce,
	}, nil
}
