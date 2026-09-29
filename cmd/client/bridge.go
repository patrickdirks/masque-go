package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/spf13/pflag"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/sys/unix"
)

// MasqueConn defines the interface for the custom methods you added to masque-go
type MasqueConn interface {
	net.Conn
	WriteMsgUDP(b, oob []byte, addr net.Addr) (n, oobn int, err error)
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr net.Addr, err error)
}

func main() {
	var proxyURITemplate string
	var ecnCMD string
	var localPort int
	var localIP string

	pflag.StringVarP(&proxyURITemplate, "template", "t", "", "URI template")
	pflag.StringVarP(&ecnCMD, "ecn", "e", "{false,0,0,0}", "ECN config: {enabled ,ect0 ,ect1 ,ce}")
	pflag.IntVarP(&localPort, "local-port", "l", 8000, "Local UDP port to listen on for picoquic")
	pflag.StringVar(&localIP, "local-ip", "127.0.0.1", "Local IP address to bind UDP listener to")
	pflag.Lookup("ecn").NoOptDefVal = "{true,2,4,6}"

	pflag.Parse()
	if proxyURITemplate == "" {
		pflag.Usage()
		os.Exit(1)
	}
	urls := pflag.Args()
	if len(urls) != 1 {
		log.Fatal("usage: client -t <template> <target-url>")
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
		KeepAlivePeriod:            2 * time.Second,
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

	raddr, err := net.ResolveUDPAddr("udp", host+":"+strconv.Itoa(int(port)))
	if err != nil {
		log.Fatalf("Failed to resolve target addr: %v", err)
	}

	//Tunnel
	log.Printf("Dialing MASQUE proxy using template...")
	pconn, _, err := cl.DialECN(context.Background(), uritemplate.MustNew(proxyURITemplate), raddr, ecnConfig)
	if err != nil {
		log.Fatal("Dialing MASQUE failed:", err)
	}
	log.Printf("Established MASQUE tunnel to %s", raddr)

	// Check ECN support
	mc, ok := pconn.(MasqueConn)
	if !ok {
		log.Fatal("The returned MASQUE connection does not implement the custom ReadMsgUDP/WriteMsgUDP methods")
	}

	// Listen on configured local IP to connect to picoquic
	parsedIP := net.ParseIP(localIP)
	if parsedIP == nil {
		log.Fatalf("Invalid local IP address: %s", localIP)
	}
	localAddr := &net.UDPAddr{IP: parsedIP, Port: localPort}
	localConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		log.Fatalf("Failed to start local UDP listener: %v", err)
	}

	// Activate ECN
	rawConn, err := localConn.SyscallConn()
	if err == nil {
		rawConn.Control(func(fd uintptr) {
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1)
		})
	}

	log.Printf("Listening for local picoquic traffic on %s", localAddr.String())

	var picoquicClientAddr atomic.Value

	// Client -> Server
	go func() {
		buf := make([]byte, 2048)
		oob := make([]byte, 1024)

		for {
			n, oobn, _, addr, err := localConn.ReadMsgUDP(buf, oob)
			if err != nil {
				log.Printf("Local UDP read error: %v", err)
				return
			}
			picoquicClientAddr.Store(addr)

			_, _, err = mc.WriteMsgUDP(buf[:n], oob[:oobn], addr)
			if err != nil {
				log.Printf("Tunnel write error: %v", err)
				return
			}
		}
	}()

	// Server -> Client
	go func() {
		buf := make([]byte, 2048)
		oob := make([]byte, 1024)

		for {
			n, oobn, _, _, err := mc.ReadMsgUDP(buf, oob)
			if err != nil {
				log.Printf("Tunnel read error: %v", err)
				return
			}

			addrVal := picoquicClientAddr.Load()
			if addrVal != nil {
				addr := addrVal.(*net.UDPAddr)
				_, _, err = localConn.WriteMsgUDP(buf[:n], oob[:oobn], addr)
				if err != nil {
					log.Printf("Local UDP write error: %v", err)
				}
			}
		}
	}()

	// Tear Down
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	log.Println("Shutting down...")
	pconn.Close()
	localConn.Close()
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
