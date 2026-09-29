package masque_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
	"unsafe"

	"github.com/quic-go/masque-go"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/sys/unix"
)

const (
	ecnECT0 = 2
	ecnCE   = 3
)

func ipv4TOSOOB(tos byte) []byte {
	oob := make([]byte, unix.CmsgSpace(4))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = unix.IPPROTO_IP
	h.Type = unix.IP_TOS
	h.SetLen(unix.CmsgLen(4))
	binary.NativeEndian.PutUint32(oob[unix.CmsgLen(0):], uint32(tos))
	return oob
}

func ecnFromOOB(t *testing.T, oob []byte) byte {
	t.Helper()
	msgs, err := unix.ParseSocketControlMessage(oob)
	require.NoError(t, err)
	for _, msg := range msgs {
		if msg.Header.Level == unix.IPPROTO_IP && (msg.Header.Type == unix.IP_TOS || msg.Header.Type == unix.IP_RECVTOS) && len(msg.Data) > 0 {
			return msg.Data[0] & 0x03
		}
	}
	t.Fatal("no TOS control message found")
	return 0
}

func TestProxyECN(t *testing.T) {
	// target server that reports the ECN codepoint of received packets
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer target.Close()
	rc, err := target.SyscallConn()
	require.NoError(t, err)
	require.NoError(t, rc.Control(func(fd uintptr) {
		require.NoError(t, unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1))
	}))

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer conn.Close()
	template := uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/masque?h={target_host}&p={target_port}", conn.LocalAddr().(*net.UDPAddr).Port))

	mux := http.NewServeMux()
	server := http3.Server{
		TLSConfig:       tlsConf,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		EnableDatagrams: true,
		Handler:         mux,
	}
	defer server.Close()
	proxy := masque.Proxy{}
	defer proxy.Close()
	ecnCh := make(chan masque.ECNState, 1)
	mux.HandleFunc("/masque", func(w http.ResponseWriter, r *http.Request) {
		req, ecnConfig, err := masque.ParseProxyRequestECN(r, template)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ecnCh <- ecnConfig
		proxy.ProxyECN(w, req, ecnConfig)
	})
	go server.Serve(conn)

	ecnConfig := masque.ECNState{Enabled: true, ContextIdECT0: 2, ContextIdECT1: 4, ContextIdCE: 6}
	tr := masque.Transport{
		TLSClientConfig: &tls.Config{ClientCAs: certPool, NextProtos: []string{http3.NextProtoH3}, InsecureSkipVerify: true},
	}
	req, err := masque.NewRequestECN(context.Background(), template, target.LocalAddr().String(), ecnConfig)
	require.NoError(t, err)
	proxiedConn, rsp, err := tr.Dial(req)
	require.NoError(t, err)
	defer proxiedConn.Close()
	require.Equal(t, "?1", rsp.Header.Get("Proxy-ECN"))
	require.Equal(t, ecnConfig, <-ecnCh)

	// client -> target: CE
	_, _, err = proxiedConn.WriteMsgUDP([]byte("foobar"), ipv4TOSOOB(ecnCE), nil)
	require.NoError(t, err)
	b := make([]byte, 1500)
	oob := make([]byte, 128)
	target.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, oobn, _, clientAddr, err := target.ReadMsgUDP(b, oob)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), b[:n])
	require.Equal(t, byte(ecnCE), ecnFromOOB(t, oob[:oobn]))

	// target -> client: ECT(0)
	_, _, err = target.WriteMsgUDP([]byte("raboof"), ipv4TOSOOB(ecnECT0), clientAddr)
	require.NoError(t, err)
	proxiedConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, oobn, _, _, err = proxiedConn.ReadMsgUDP(b, oob)
	require.NoError(t, err)
	require.Equal(t, []byte("raboof"), b[:n])
	require.Equal(t, byte(ecnECT0), ecnFromOOB(t, oob[:oobn]))

	// client -> target, forwarding the oob exactly as received from a local socket (like cmd/client/bridge.go).
	// On macOS, the received control message has type IP_RECVTOS instead of IP_TOS.
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer local.Close()
	lrc, err := local.SyscallConn()
	require.NoError(t, err)
	require.NoError(t, lrc.Control(func(fd uintptr) {
		require.NoError(t, unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1))
	}))
	app, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer app.Close()
	_, _, err = app.WriteMsgUDP([]byte("bridged"), ipv4TOSOOB(ecnCE), local.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	local.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, oobn, _, _, err = local.ReadMsgUDP(b, oob)
	require.NoError(t, err)
	_, _, err = proxiedConn.WriteMsgUDP(b[:n], oob[:oobn], nil)
	require.NoError(t, err)
	n, oobn, _, _, err = target.ReadMsgUDP(b, oob)
	require.NoError(t, err)
	require.Equal(t, []byte("bridged"), b[:n])
	require.Equal(t, byte(ecnCE), ecnFromOOB(t, oob[:oobn]))
}
