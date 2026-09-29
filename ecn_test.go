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
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/sys/unix"
)

// ECN codepoints (RFC 3168)
const (
	ecnNotECT = 0
	ecnECT1   = 1
	ecnECT0   = 2
	ecnCE     = 3
)

var testECNConfig = masque.ECNState{Enabled: true, ContextIdECT0: 2, ContextIdECT1: 4, ContextIdCE: 6}

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

// newECNUDPConn returns a UDP socket on localhost that reports the TOS byte of received packets.
func newECNUDPConn(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	rc, err := conn.SyscallConn()
	require.NoError(t, err)
	require.NoError(t, rc.Control(func(fd uintptr) {
		require.NoError(t, unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1))
	}))
	return conn
}

func readWithECN(t *testing.T, conn *net.UDPConn) ([]byte, byte, *net.UDPAddr) {
	t.Helper()
	b := make([]byte, 1500)
	oob := make([]byte, 128)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, oobn, _, addr, err := conn.ReadMsgUDP(b, oob)
	require.NoError(t, err)
	return b[:n], ecnFromOOB(t, oob[:oobn]), addr
}

func newECNTestTransport() *masque.Transport {
	return &masque.Transport{
		TLSClientConfig: &tls.Config{ClientCAs: certPool, NextProtos: []string{http3.NextProtoH3}, InsecureSkipVerify: true},
	}
}

// runECNProxy starts a masque.Proxy that negotiates ECN using the Proxy-ECN header.
// The ECN config parsed from each request is sent on the returned channel.
func runECNProxy(t *testing.T) (*uritemplate.Template, <-chan masque.ECNState) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	template := uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/masque?h={target_host}&p={target_port}", conn.LocalAddr().(*net.UDPAddr).Port))

	mux := http.NewServeMux()
	server := http3.Server{
		TLSConfig:       tlsConf,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		EnableDatagrams: true,
		Handler:         mux,
	}
	proxy := &masque.Proxy{}
	t.Cleanup(func() {
		proxy.Close()
		server.Close()
	})
	ecnCh := make(chan masque.ECNState, 10)
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
	return template, ecnCh
}

// setupECNConn dials a masque.Conn to a plain HTTP/3 handler, which gives the test direct access to the
// request stream. This allows sending and inspecting datagrams with arbitrary Context IDs.
// If confirm is set, the handler confirms ECN support using the Proxy-ECN header.
func setupECNConn(t *testing.T, ecnConfig masque.ECNState, confirm bool) (*http3.Stream, *masque.Conn) {
	t.Helper()
	strChan := make(chan *http3.Stream, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/masque", func(w http.ResponseWriter, r *http.Request) {
		if confirm {
			w.Header().Set("Proxy-ECN", "?1")
		}
		strChan <- w.(http3.HTTPStreamer).HTTPStream()
	})
	server := http3.Server{
		TLSConfig:       tlsConf,
		Handler:         mux,
		EnableDatagrams: true,
	}
	t.Cleanup(func() { server.Close() })
	serverConn := newUDPConnLocalhost(t)
	go server.Serve(serverConn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, err := masque.NewRequestECN(ctx,
		uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/masque?h={target_host}&p={target_port}", serverConn.LocalAddr().(*net.UDPAddr).Port)),
		"127.0.0.1:1234",
		ecnConfig,
	)
	require.NoError(t, err)
	conn, rsp, err := newECNTestTransport().Dial(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rsp.StatusCode)
	t.Cleanup(func() { conn.Close() })

	select {
	case str := <-strChan:
		return str, conn
	case <-time.After(time.Second):
		t.Fatal("timeout")
		return nil, nil
	}
}

func sendDatagram(t *testing.T, str *http3.Stream, contextID uint64, payload string) {
	t.Helper()
	require.NoError(t, str.SendDatagram(append(quicvarint.Append(nil, contextID), payload...)))
}

func receiveDatagram(t *testing.T, str *http3.Stream) (uint64, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := str.ReceiveDatagram(ctx)
	require.NoError(t, err)
	contextID, n, err := quicvarint.Parse(data)
	require.NoError(t, err)
	return contextID, string(data[n:])
}

func TestParseProxyECN(t *testing.T) {
	for _, tc := range []struct {
		name     string
		header   string
		expected masque.ECNState
		err      string
	}{
		{name: "empty header", header: "", expected: masque.ECNState{}},
		{name: "disabled", header: "?0", expected: masque.ECNState{}},
		{name: "enabled", header: "?1; ect1=4; ect0=2; ce=6", expected: testECNConfig},
		{name: "enabled, different order and spacing", header: "?1;ce=6;ECT0=2;  ect1=4", expected: testECNConfig},
		{name: "unknown parameters are ignored", header: "?1; ect1=4; ect0=2; ce=6; foo=8", expected: testECNConfig},
		{name: "invalid boolean", header: "?2; ect1=4; ect0=2; ce=6", err: "must start with ?0 or ?1"},
		{name: "not a number", header: "?1; ect1=four; ect0=2; ce=6", err: "invalid ECN ID for ect1"},
		{name: "missing ID", header: "?1; ect1=4; ect0=2", err: "incomplete ECN parameters"},
		{name: "odd ID for ECT(0)", header: "?1; ect1=4; ect0=3; ce=6", err: "ECT0 must be even"},
		{name: "odd ID for ECT(1)", header: "?1; ect1=5; ect0=2; ce=6", err: "ECT1 must be even"},
		{name: "odd ID for CE", header: "?1; ect1=4; ect0=2; ce=7", err: "CE must be even"},
		{name: "ECT(0) and ECT(1) share an ID", header: "?1; ect1=2; ect0=2; ce=6", err: "ECT1 and ECT0 cannot be the same"},
		{name: "ECT(0) and CE share an ID", header: "?1; ect1=4; ect0=6; ce=6", err: "ECT0 and CE cannot be the same"},
		{name: "ECT(1) and CE share an ID", header: "?1; ect1=6; ect0=2; ce=6", err: "ECT1 and CE cannot be the same"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, err := masque.ParseProxyECN(tc.header)
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, state)
		})
	}
}

func TestParseProxyRequestECN(t *testing.T) {
	template := uritemplate.MustNew("https://localhost:1234/masque?h={target_host}&p={target_port}")

	t.Run("without Proxy-ECN header", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque?h=localhost&p=1337")
		r, ecnConfig, err := masque.ParseProxyRequestECN(req, template)
		require.NoError(t, err)
		require.Equal(t, "localhost:1337", r.Target)
		require.False(t, ecnConfig.Enabled)
	})

	t.Run("with Proxy-ECN header", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque?h=localhost&p=1337")
		req.Header.Set("Proxy-ECN", "?1; ect1=4; ect0=2; ce=6")
		r, ecnConfig, err := masque.ParseProxyRequestECN(req, template)
		require.NoError(t, err)
		require.Equal(t, "localhost:1337", r.Target)
		require.Equal(t, testECNConfig, ecnConfig)
	})

	t.Run("invalid Proxy-ECN header", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque?h=localhost&p=1337")
		req.Header.Set("Proxy-ECN", "?1; ect1=3; ect0=2; ce=6")
		_, _, err := masque.ParseProxyRequestECN(req, template)
		require.ErrorContains(t, err, "invalid Proxy-ECN header")
		require.Equal(t, http.StatusBadRequest, err.(*masque.ProxyRequestParseError).HTTPStatus)

		// ParseProxyRequest rejects the request as well
		_, err = masque.ParseProxyRequest(req, template)
		require.ErrorContains(t, err, "invalid Proxy-ECN header")
	})
}

func TestNewRequestECN(t *testing.T) {
	template := uritemplate.MustNew("https://localhost:1234/masque?h={target_host}&p={target_port}")

	t.Run("enabled", func(t *testing.T) {
		req, err := masque.NewRequestECN(context.Background(), template, "localhost:1337", testECNConfig)
		require.NoError(t, err)
		require.Equal(t, "?1; ect1=4; ect0=2; ce=6", req.Header().Get("Proxy-ECN"))
		// the header can be parsed by the proxy
		state, err := masque.ParseProxyECN(req.Header().Get("Proxy-ECN"))
		require.NoError(t, err)
		require.Equal(t, testECNConfig, state)
	})

	t.Run("disabled", func(t *testing.T) {
		req, err := masque.NewRequestECN(context.Background(), template, "localhost:1337", masque.ECNState{ContextIdECT0: 2, ContextIdECT1: 4, ContextIdCE: 6})
		require.NoError(t, err)
		require.Empty(t, req.Header().Values("Proxy-ECN"))
	})

	t.Run("NewRequest doesn't use ECN", func(t *testing.T) {
		req, err := masque.NewRequest(context.Background(), template, "localhost:1337")
		require.NoError(t, err)
		require.Empty(t, req.Header().Values("Proxy-ECN"))
	})
}

func TestConnECNMapping(t *testing.T) {
	str, conn := setupECNConn(t, testECNConfig, true)

	t.Run("sending", func(t *testing.T) {
		for _, tc := range []struct {
			ecn       byte
			contextID uint64
		}{
			{ecnNotECT, 0},
			{ecnECT1, testECNConfig.ContextIdECT1},
			{ecnECT0, testECNConfig.ContextIdECT0},
			{ecnCE, testECNConfig.ContextIdCE},
		} {
			_, _, err := conn.WriteMsgUDP([]byte("foobar"), ipv4TOSOOB(tc.ecn), nil)
			require.NoError(t, err)
			contextID, payload := receiveDatagram(t, str)
			require.Equal(t, tc.contextID, contextID, "ECN codepoint %d", tc.ecn)
			require.Equal(t, "foobar", payload)
		}
	})

	t.Run("sending without oob", func(t *testing.T) {
		_, err := conn.WriteTo([]byte("foobar"), nil)
		require.NoError(t, err)
		contextID, _ := receiveDatagram(t, str)
		require.Zero(t, contextID)

		_, err = conn.Write([]byte("foobar"))
		require.NoError(t, err)
		contextID, _ = receiveDatagram(t, str)
		require.Zero(t, contextID)
	})

	t.Run("sending with invalid oob", func(t *testing.T) {
		oob := ipv4TOSOOB(ecnCE)
		(*unix.Cmsghdr)(unsafe.Pointer(&oob[0])).SetLen(len(oob) + 100) // length exceeds the buffer
		_, _, err := conn.WriteMsgUDP([]byte("foobar"), oob, nil)
		require.ErrorContains(t, err, "failed to parse oob")
	})

	t.Run("receiving", func(t *testing.T) {
		for _, tc := range []struct {
			contextID uint64
			ecn       byte
		}{
			{0, ecnNotECT},
			{testECNConfig.ContextIdECT1, ecnECT1},
			{testECNConfig.ContextIdECT0, ecnECT0},
			{testECNConfig.ContextIdCE, ecnCE},
		} {
			sendDatagram(t, str, tc.contextID, "raboof")
			b := make([]byte, 1500)
			oob := make([]byte, 128)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, oobn, _, _, err := conn.ReadMsgUDP(b, oob)
			require.NoError(t, err)
			require.Equal(t, "raboof", string(b[:n]))
			require.Equal(t, tc.ecn, ecnFromOOB(t, oob[:oobn]), "Context ID %d", tc.contextID)
		}
	})

	t.Run("receiving drops unknown Context IDs", func(t *testing.T) {
		sendDatagram(t, str, 8, "unknown")
		sendDatagram(t, str, testECNConfig.ContextIdCE, "known")
		b := make([]byte, 1500)
		oob := make([]byte, 128)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, oobn, _, _, err := conn.ReadMsgUDP(b, oob)
		require.NoError(t, err)
		require.Equal(t, "known", string(b[:n]))
		require.Equal(t, byte(ecnCE), ecnFromOOB(t, oob[:oobn]))
	})

	t.Run("receiving with a small oob buffer", func(t *testing.T) {
		sendDatagram(t, str, testECNConfig.ContextIdCE, "foobar")
		b := make([]byte, 1500)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, oobn, _, _, err := conn.ReadMsgUDP(b, nil)
		require.NoError(t, err)
		require.Equal(t, "foobar", string(b[:n]))
		require.Zero(t, oobn)
	})
}

func TestConnECNNotConfirmed(t *testing.T) {
	// The client requests ECN, but the proxy doesn't confirm it.
	str, conn := setupECNConn(t, testECNConfig, false)

	// ECN markings are not forwarded
	_, _, err := conn.WriteMsgUDP([]byte("foobar"), ipv4TOSOOB(ecnCE), nil)
	require.NoError(t, err)
	contextID, payload := receiveDatagram(t, str)
	require.Zero(t, contextID)
	require.Equal(t, "foobar", payload)

	// datagrams using the ECN Context IDs are dropped
	sendDatagram(t, str, testECNConfig.ContextIdCE, "ce")
	sendDatagram(t, str, 0, "plain")
	b := make([]byte, 1500)
	oob := make([]byte, 128)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, oobn, _, _, err := conn.ReadMsgUDP(b, oob)
	require.NoError(t, err)
	require.Equal(t, "plain", string(b[:n]))
	require.Equal(t, byte(ecnNotECT), ecnFromOOB(t, oob[:oobn]))
}

func TestProxyECN(t *testing.T) {
	target := newECNUDPConn(t)
	template, ecnCh := runECNProxy(t)

	req, err := masque.NewRequestECN(context.Background(), template, target.LocalAddr().String(), testECNConfig)
	require.NoError(t, err)
	proxiedConn, rsp, err := newECNTestTransport().Dial(req)
	require.NoError(t, err)
	defer proxiedConn.Close()
	require.Equal(t, "?1", rsp.Header.Get("Proxy-ECN"))
	require.Equal(t, testECNConfig, <-ecnCh)

	// client -> target: every codepoint arrives unchanged at the target
	var clientAddr *net.UDPAddr
	for _, codepoint := range []byte{ecnNotECT, ecnECT1, ecnECT0, ecnCE} {
		_, _, err = proxiedConn.WriteMsgUDP([]byte("foobar"), ipv4TOSOOB(codepoint), nil)
		require.NoError(t, err)
		var data []byte
		var ecn byte
		data, ecn, clientAddr = readWithECN(t, target)
		require.Equal(t, "foobar", string(data))
		require.Equal(t, codepoint, ecn, "ECN codepoint %d", codepoint)
	}

	// target -> client: every codepoint is mapped to its Context ID and back
	for _, codepoint := range []byte{ecnNotECT, ecnECT1, ecnECT0, ecnCE} {
		_, _, err = target.WriteMsgUDP([]byte("raboof"), ipv4TOSOOB(codepoint), clientAddr)
		require.NoError(t, err)
		b := make([]byte, 1500)
		oob := make([]byte, 128)
		proxiedConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, oobn, _, _, err := proxiedConn.ReadMsgUDP(b, oob)
		require.NoError(t, err)
		require.Equal(t, "raboof", string(b[:n]))
		require.Equal(t, codepoint, ecnFromOOB(t, oob[:oobn]))
	}

	// client -> target, forwarding the oob exactly as received from a local socket (like cmd/client/bridge.go).
	// On macOS, the received control message has type IP_RECVTOS instead of IP_TOS.
	local := newECNUDPConn(t)
	app, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer app.Close()
	_, _, err = app.WriteMsgUDP([]byte("bridged"), ipv4TOSOOB(ecnCE), local.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	b := make([]byte, 1500)
	oob := make([]byte, 128)
	local.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, oobn, _, _, err := local.ReadMsgUDP(b, oob)
	require.NoError(t, err)
	_, _, err = proxiedConn.WriteMsgUDP(b[:n], oob[:oobn], nil)
	require.NoError(t, err)
	data, ecn, _ := readWithECN(t, target)
	require.Equal(t, "bridged", string(data))
	require.Equal(t, byte(ecnCE), ecn)
}

func TestProxyWithoutECN(t *testing.T) {
	target := newECNUDPConn(t)
	template, ecnCh := runECNProxy(t)

	req, err := masque.NewRequest(context.Background(), template, target.LocalAddr().String())
	require.NoError(t, err)
	proxiedConn, rsp, err := newECNTestTransport().Dial(req)
	require.NoError(t, err)
	defer proxiedConn.Close()
	require.Empty(t, rsp.Header.Values("Proxy-ECN"))
	require.False(t, (<-ecnCh).Enabled)

	// ECN markings of the target are not forwarded to the client
	_, err = proxiedConn.WriteTo([]byte("foobar"), nil)
	require.NoError(t, err)
	_, ecn, clientAddr := readWithECN(t, target)
	require.Equal(t, byte(ecnNotECT), ecn)
	_, _, err = target.WriteMsgUDP([]byte("raboof"), ipv4TOSOOB(ecnCE), clientAddr)
	require.NoError(t, err)
	b := make([]byte, 1500)
	oob := make([]byte, 128)
	proxiedConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, oobn, _, _, err := proxiedConn.ReadMsgUDP(b, oob)
	require.NoError(t, err)
	require.Equal(t, "raboof", string(b[:n]))
	require.Equal(t, byte(ecnNotECT), ecnFromOOB(t, oob[:oobn]))
}

// The ECN config is negotiated per request.
// A flow without ECN must not change the ECN config of an existing flow.
func TestProxyECNPerFlow(t *testing.T) {
	target := newECNUDPConn(t)
	template, ecnCh := runECNProxy(t)
	tr := newECNTestTransport()

	req, err := masque.NewRequestECN(context.Background(), template, target.LocalAddr().String(), testECNConfig)
	require.NoError(t, err)
	ecnConn, _, err := tr.Dial(req)
	require.NoError(t, err)
	defer ecnConn.Close()
	require.True(t, (<-ecnCh).Enabled)

	req, err = masque.NewRequest(context.Background(), template, target.LocalAddr().String())
	require.NoError(t, err)
	plainConn, _, err := tr.Dial(req)
	require.NoError(t, err)
	defer plainConn.Close()
	require.False(t, (<-ecnCh).Enabled)

	_, _, err = ecnConn.WriteMsgUDP([]byte("ecn"), ipv4TOSOOB(ecnCE), nil)
	require.NoError(t, err)
	data, ecn, _ := readWithECN(t, target)
	require.Equal(t, "ecn", string(data))
	require.Equal(t, byte(ecnCE), ecn)

	_, _, err = plainConn.WriteMsgUDP([]byte("plain"), ipv4TOSOOB(ecnCE), nil)
	require.NoError(t, err)
	data, ecn, _ = readWithECN(t, target)
	require.Equal(t, "plain", string(data))
	require.Equal(t, byte(ecnNotECT), ecn)
}
