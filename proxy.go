package masque

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
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
	mx       sync.Mutex
	closed   bool
	refCount sync.WaitGroup // counter for the Go routines spawned in Upgrade
	closers  map[io.Closer]struct{}
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
	s.mx.Lock()
	if s.closed {
		s.mx.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}
	s.mx.Unlock()

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
		print("Send:" + strconv.Itoa(int(contextID)) + "\n")
		if contextID > 3 {
			// Drop this datagram. We currently only support proxying of UDP payloads.
			continue
		}
		if len(data[n:]) > maxUDPPayloadSize {
			log.Printf("dropping datagram larger than MTU (%d > %d)", len(data[n:]), maxUDPPayloadSize)
			continue
		}
		var layer int
		var typeVal int

		tosByte := contextID & 0x03
		oob := make([]byte, unix.CmsgSpace(4))
		//if _, err := conn.Write(data[n:]); err != nil {
		addr := conn.LocalAddr().(*net.UDPAddr)
		if addr.IP.To4() != nil {
			// IPv4
			layer = unix.IPPROTO_IP
			typeVal = unix.IP_TOS // Or IP_RECVTOS depending on platform, usually IP_TOS for sending
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

		// 6. Send the message
		_, _, _ = conn.WriteMsgUDP(data[n:], oob, nil)
	}
}

/*
	func (s *Proxy) proxyConnReceive(conn *net.UDPConn, str *http3.Stream) error {
		print("Rec")

		// 1 byte for Context ID + Max UDP Payload
		b := make([]byte, 1+maxUDPPayloadSize)

		// OOB buffer
		var oobBuf [128]byte

		for {
			// Read into b[1:] to leave space for the ECN byte at b[0]
			n, oobn, _, _, err := conn.ReadMsgUDP(b[1:], oobBuf[:])
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

			// --- Extract ECN using 'unix' package ---
			ecn := 0
			// Parse the raw OOB bytes
			if oobn > 0 {
				print("W")
				// Manually parse OOB data to extract ECN
				oob := oobBuf[:oobn]
				msgs, _ := unix.ParseSocketControlMessage(oob)
				for _, msg := range msgs {
					print("Y")
					if (msg.Header.Level == unix.IPPROTO_IP && msg.Header.Type == unix.IP_TOS) ||
						(msg.Header.Level == unix.IPPROTO_IPV6 && msg.Header.Type == unix.IPV6_TCLASS) {
						print("Z")
						if len(msg.Data) > 0 {
							print("X")
							ecn = int(msg.Data[0]) & 0x03
						}
					}
				}
			}

			print("P1")

			// --- Set Context ID ---
			b[0] = byte(2)
			print("\nECN")
			print(ecn)
			print("\n")
			if err := str.SendDatagram(b[:1+n]); err != nil {
				return err
			}
		}
	}
*/
func (s *Proxy) proxyConnReceive(conn *net.UDPConn, str *http3.Stream) error {
	// [FIX] Enable ECN reading via SyscallConn.
	// golang.org/x/net/ipv4 does not expose a FlagTOS constant, so we use low-level setsockopt.
	if sc, err := conn.SyscallConn(); err == nil {
		sc.Control(func(fd uintptr) {
			// IPv4: IP_RECVTOS (receive Type of Service / ECN)
			if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1); err != nil {
				log.Printf("masque: warning: failed to enable IPv4 ECN: %v", err)
			}
			// IPv6: IPV6_RECVTCLASS (receive Traffic Class / ECN)
			if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1); err != nil {
				// Ignore EINVAL (invalid argument), which happens if the socket is IPv4-only.
				if !errors.Is(err, unix.EINVAL) {
					log.Printf("masque: warning: failed to enable IPv6 ECN: %v", err)
				}
			}
		})
	} else {
		log.Printf("masque: warning: failed to get SyscallConn to enable ECN: %v", err)
	}

	// 1 byte for Context ID + Max UDP Payload
	// Ensure maxUDPPayloadSize is defined in your package (usually 1200-1500)
	b := make([]byte, 1+maxUDPPayloadSize)

	// OOB buffer to read ECN bits from the kernel
	var oobBuf [128]byte

	for {
		// Read into b[1:] to leave space for the Context ID at b[0]
		n, oobn, _, _, err := conn.ReadMsgUDP(b[1:], oobBuf[:])
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

		// --- Extract ECN ---
		ecn := 0 // Default to 0 (Not-ECT) if no OOB data is found

		if oobn > 0 {
			// Parse the raw OOB bytes
			msgs, _ := unix.ParseSocketControlMessage(oobBuf[:oobn])
			for _, msg := range msgs {
				// [FIX] Check for multiple OOB types to support both Linux and macOS/BSD.
				// macOS returns type IP_RECVTOS (3) whereas Linux returns IP_TOS (1).
				isIPv4TOS := msg.Header.Level == unix.IPPROTO_IP &&
					(msg.Header.Type == unix.IP_TOS || msg.Header.Type == unix.IP_RECVTOS)

				isIPv6TClass := msg.Header.Level == unix.IPPROTO_IPV6 &&
					(msg.Header.Type == unix.IPV6_TCLASS || msg.Header.Type == unix.IPV6_RECVTCLASS)

				if isIPv4TOS || isIPv6TClass {
					if len(msg.Data) > 0 {
						// Extract ECN (last 2 bits of the TOS byte)
						ecn = int(msg.Data[0]) & 0x03
						break // Found it, no need to check other messages
					}
				}
			}
		}

		// --- Set Context ID ---
		// Map ECN (0-3) directly to Masque Context ID (0-3)
		b[0] = byte(ecn)

		// Send the Datagram: [Context ID] + [Payload]
		if err := str.SendDatagram(b[:1+n]); err != nil {
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
