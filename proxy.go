package masque

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"unsafe"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/sys/unix"
)

const (
	uriTemplateTargetHost = "target_host"
	uriTemplateTargetPort = "target_port"
)

const maxUDPPayloadSize = 1500

var contextIDZero = quicvarint.Append([]byte{}, 0)

type proxyEntry struct {
	str  *http3.Stream
	conn *net.UDPConn
}

func (e proxyEntry) Close() error {
	e.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
	return errors.Join(e.str.Close(), e.conn.Close())
}

// A Proxy is an RFC 9298 CONNECT-UDP proxy.

type Proxy struct {
	mx        sync.Mutex
	closed    bool
	refCount  sync.WaitGroup // counter for the Go routines spawned in Upgrade
	closers   map[io.Closer]struct{}
	ecnConfig ECNState
}

func errToStatus(err error) int {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		// Consistent with RFC 9209 Section 2.3.1.
		return http.StatusGatewayTimeout
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		// Recommended by RFC 9209 Section 2.3.2.
		return http.StatusBadGateway
	}
	var addrErr *net.AddrError
	var parseError *net.ParseError
	if errors.As(err, &addrErr) || errors.As(err, &parseError) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func dnsErrorToProxyStatus(proxyStatus *httpsfv.Item, dnsError *net.DNSError) {
	if dnsError.Timeout() {
		proxyStatus.Params.Add("error", "dns_timeout")
	} else {
		proxyStatus.Params.Add("error", "dns_error")
		if dnsError.IsNotFound {
			// "Negative response" isn't a real RCODE, but it is included
			// in RFC 8499 Section 3 as a sort of meta/pseudo-RCODE like NODATA,
			// and this section is referenced by the definition of the "rcode"
			// parameter.
			proxyStatus.Params.Add("rcode", "Negative response")
		} else {
			// DNS intermediaries normally convert miscellaneous errors to SERVFAIL.
			proxyStatus.Params.Add("rcode", "SERVFAIL")
		}
	}
}

// Proxy proxies a request on a newly created connected UDP socket.
// For more control over the UDP socket, use ProxyConnectedSocket.
// Applications may add custom header fields to the response header,
// but MUST NOT call WriteHeader on the http.ResponseWriter.
func (s *Proxy) Proxy(w http.ResponseWriter, r *Request) error {
	ecnConfig := ECNState{false, 0, 0, 0}
	return s.ProxyECN(w, r, ecnConfig)

}

func (s *Proxy) ProxyECN(w http.ResponseWriter, r *Request, ecnConfig ECNState) error {
	s.mx.Lock()
	if s.closed {
		s.mx.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}
	s.mx.Unlock()
	s.ecnConfig = ecnConfig
	proxyStatus := httpsfv.NewItem(r.Host)
	// Adds the proxy status to the header.  Returns
	// the input error, or a new one if serialization fails.
	writeProxyStatus := func(err error) error {
		if err != nil {
			proxyStatus.Params.Add("details", err.Error())
		}
		proxyStatusVal, marshalErr := httpsfv.Marshal(proxyStatus)
		if marshalErr != nil {
			return marshalErr
		}
		w.Header().Add("Proxy-Status", proxyStatusVal)
		if s.ecnConfig.Enabled {
			w.Header().Set("Proxy-ECN", "?1")
		}
		return err
	}

	addr, err := net.ResolveUDPAddr("udp", r.Target)
	if err != nil {
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) {
			dnsErrorToProxyStatus(&proxyStatus, dnsError)
		}
		err = writeProxyStatus(err)
		w.WriteHeader(errToStatus(err))
		return err
	}
	proxyStatus.Params.Add("next-hop", addr.String())

	conn, err := net.DialUDP("udp", nil, addr)

	if err != nil {
		proxyStatus.Params.Add("error", "destination_ip_unroutable")
		err = writeProxyStatus(err)
		w.WriteHeader(errToStatus(err))
		return err
	}
	defer conn.Close()

	if err = writeProxyStatus(nil); err != nil {
		w.WriteHeader(errToStatus(err))
		return err
	}
	return s.ProxyConnectedSocket(w, r, conn)
}

// ProxyConnectedSocket proxies a request on a connected UDP socket.
// Applications may add custom header fields such as Proxy-Status
// to the response header, but MUST NOT call WriteHeader on the
// http.ResponseWriter. It closes the connection before returning.

func (s *Proxy) ProxyConnectedSocket(w http.ResponseWriter, _ *Request, conn *net.UDPConn) error {
	s.mx.Lock()
	if s.closed {
		s.mx.Unlock()
		conn.Close()
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}

	str := w.(http3.HTTPStreamer).HTTPStream()
	entry := proxyEntry{str: str, conn: conn}

	if s.closers == nil {
		s.closers = make(map[io.Closer]struct{})
	}
	s.closers[entry] = struct{}{}

	s.refCount.Add(1)
	defer s.refCount.Done()
	s.mx.Unlock()

	w.Header().Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	w.WriteHeader(http.StatusOK)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := s.proxyConnSend(conn, str); err != nil {
			log.Printf("proxying send side to %s failed: %v", conn.RemoteAddr(), err)
		}
		str.Close()
	}()
	go func() {
		defer wg.Done()
		if err := s.proxyConnReceive(conn, str); err != nil {
			s.mx.Lock()
			closed := s.closed
			s.mx.Unlock()
			if !closed {
				log.Printf("proxying receive side to %s failed: %v", conn.RemoteAddr(), err)
			}
		}
		str.Close()
	}()
	// discard all capsules sent on the request stream
	if err := skipCapsules(quicvarint.NewReader(str)); err == io.EOF {
		log.Printf("reading from request stream failed: %v", err)
	}
	str.Close()
	conn.Close()
	wg.Wait()
	s.mx.Lock()
	delete(s.closers, entry)
	s.mx.Unlock()
	return nil
}

func (s *Proxy) proxyConnSend(conn *net.UDPConn, str *http3.Stream) error {
	for {
		data, err := str.ReceiveDatagram(context.Background())
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		contextID, n, err := quicvarint.Parse(data)
		if err != nil {
			return err
		}
		//Map Context-ID to ECN-bits, drop invalid IDs
		tosByte := 0
		if s.ecnConfig.Enabled {
			switch contextID {
			case 0:
				tosByte = 0
			case s.ecnConfig.ContextIdECT1:
				tosByte = 2
			case s.ecnConfig.ContextIdECT0:
				tosByte = 1
			case s.ecnConfig.ContextIdCE:
				tosByte = 3
			default:
				log.Printf("dropping data using invalid ContextID (%d)", contextID)
				continue
			}
		} else {
			if contextID != 0 {
				log.Printf("dropping data using invalid ContextID (%d) when ECN is disabled", contextID)
				continue
			}
		}
		if len(data[n:]) > maxUDPPayloadSize {
			log.Printf("dropping datagram larger than MTU (%d > %d)", len(data[n:]), maxUDPPayloadSize)
			continue
		}

		// Prepare oob to write the ECN bytes
		var layer int
		var typeVal int
		oob := make([]byte, unix.CmsgSpace(4))

		//Check if connection is using IPv4 or IPv6
		addr := conn.LocalAddr().(*net.UDPAddr)
		if addr.IP.To4() != nil {
			// IPv4
			layer = unix.IPPROTO_IP
			typeVal = unix.IP_TOS
		} else {
			// IPv6
			layer = unix.IPPROTO_IPV6
			typeVal = unix.IPV6_TCLASS
		}

		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		cmsghdr.Level = int32(layer)
		cmsghdr.Type = int32(typeVal)
		cmsghdr.SetLen(unix.CmsgLen(4))
		dataPtr := uintptr(unsafe.Pointer(&oob[0])) + uintptr(unix.CmsgLen(0))
		*(*uint32)(unsafe.Pointer(dataPtr)) = uint32(tosByte)

		// Send the message using WriteMsqUDP
		if _, _, err := conn.WriteMsgUDP(data[n:], oob, nil); err != nil {
			log.Printf("masque: failed to send message (%v)", err)
		}
	}
}

func (s *Proxy) proxyConnReceive(conn *net.UDPConn, str *http3.Stream) error {
	// Enable ECN reading via SyscallConn.
	// TODO: Verify Linux support, currently only tested on MacOS
	if sc, err := conn.SyscallConn(); err == nil {
		sc.Control(func(fd uintptr) {
			// IPv4
			if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1); err != nil {
				log.Printf("masque: warning: failed to enable IPv4 ECN: %v", err)
			}
			// IPv6
			if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1); err != nil {
				// Ignore EINVAL (invalid argument) if the socket is IPv4-only.
				if !errors.Is(err, unix.EINVAL) {
					log.Printf("masque: warning: failed to enable IPv6 ECN: %v", err)
				}
			}
		})
	} else {
		log.Printf("masque: warning: failed to get SyscallConn to enable ECN: %v", err)
	}
	// Buffer for message
	b := make([]byte, maxUDPPayloadSize)

	// Buffer for OOB
	var oobBuf [128]byte

	for {
		n, oobn, _, _, err := conn.ReadMsgUDP(b[:], oobBuf[:])
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		if n > maxUDPPayloadSize {
			log.Printf("dropping UDP packet larger than MTU")
			continue
		}

		ecn := 0

		if oobn > 0 {
			// Parse the raw OOB bytes
			msgs, _ := unix.ParseSocketControlMessage(oobBuf[:oobn])
			for _, msg := range msgs {
				// macOS returns type IP_RECVTOS (3) whereas Linux returns IP_TOS (1) -> TODO: Check for better way
				isIPv4TOS := msg.Header.Level == unix.IPPROTO_IP &&
					(msg.Header.Type == unix.IP_TOS || msg.Header.Type == unix.IP_RECVTOS)

				isIPv6TClass := msg.Header.Level == unix.IPPROTO_IPV6 &&
					(msg.Header.Type == unix.IPV6_TCLASS || msg.Header.Type == unix.IPV6_RECVTCLASS)

				if isIPv4TOS || isIPv6TClass {
					if len(msg.Data) > 0 {
						// Extract ECN
						ecn = int(msg.Data[0]) & 0x03
						break
					}
				}
			}
		}

		//Map ECN <-> ContextID
		var contextId uint64 = 0
		if s.ecnConfig.Enabled {
			switch ecn {
			case 0:
				contextId = 0
			case 1:
				contextId = s.ecnConfig.ContextIdECT1
			case 2:
				contextId = s.ecnConfig.ContextIdECT0
			case 3:
				contextId = s.ecnConfig.ContextIdCE
			}
		}
		//Convert Contect ID to Quic Variable Length Encoding
		cID := quicvarint.Append([]byte{}, contextId)
		//Prepend ContextID
		m := append(cID, b...)
		// Send the Datagram
		if err := str.SendDatagram(m[:len(cID)+n]); err != nil {
			return err
		}
	}
}

// Close closes the proxy, immediately terminating all proxied flows.

func (s *Proxy) Close() error {
	s.mx.Lock()
	s.closed = true
	var errs []error
	for closer := range s.closers {
		errs = append(errs, closer.Close())
	}
	s.mx.Unlock()

	s.refCount.Wait()
	s.closers = nil
	return errors.Join(errs...)
}
