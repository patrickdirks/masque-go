package masque

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/sys/unix"
)

type masqueAddr struct{ string }

func (m masqueAddr) Network() string { return "connect-udp" }
func (m masqueAddr) String() string  { return m.string }

var _ net.Addr = masqueAddr{}

type http3Stream interface {
	io.ReadWriteCloser
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
	CancelRead(quic.StreamErrorCode)
}

var (
	_ http3Stream = &http3.Stream{}
	_ http3Stream = &http3.RequestStream{}
)

type proxiedConn struct {
	str        http3Stream
	localAddr  net.Addr
	remoteAddr net.Addr

	closed   atomic.Bool // set when Close is called
	readDone chan struct{}

	deadlineMx        sync.Mutex
	readCtx           context.Context
	readCtxCancel     context.CancelFunc
	deadline          time.Time
	readDeadlineTimer *time.Timer
}

var _ net.PacketConn = &proxiedConn{}

func newProxiedConn(str http3Stream, local, remote net.Addr) *proxiedConn {
	c := &proxiedConn{
		str:        str,
		localAddr:  local,
		remoteAddr: remote,
		readDone:   make(chan struct{}),
	}
	c.readCtx, c.readCtxCancel = context.WithCancel(context.Background())
	go func() {
		defer close(c.readDone)
		if err := skipCapsules(quicvarint.NewReader(str)); err != io.EOF && !c.closed.Load() {
			log.Printf("reading from request stream failed: %v", err)
		}
		str.Close()
	}()
	return c
}

func (c *proxiedConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	print("OldRead\n")
start:

	c.deadlineMx.Lock()
	ctx := c.readCtx
	c.deadlineMx.Unlock()
	data, err := c.str.ReceiveDatagram(ctx)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			return 0, nil, err
		}
		// The context is cancelled asynchronously (in a Go routine spawned from time.AfterFunc).
		// We need to check if a new deadline has already been set.
		c.deadlineMx.Lock()
		restart := time.Now().Before(c.deadline)
		c.deadlineMx.Unlock()
		if restart {
			goto start
		}
		return 0, nil, os.ErrDeadlineExceeded
	}
	contextID, n, err := quicvarint.Parse(data)
	if err != nil {
		return 0, nil, fmt.Errorf("masque: malformed datagram: %w", err)
	}
	if contextID != 0 {
		// Drop this datagram. We currently only support proxying of UDP payloads.
		goto start
	}
	// If b is too small, additional bytes are discarded.
	// This mirrors the behavior of large UDP datagrams received on a UDP socket (on Linux).
	return copy(b, data[n:]), c.remoteAddr, nil
}

// WriteTo sends a UDP datagram to the target.
// The net.Addr parameter is ignored.

func (c *proxiedConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	print("OldWrite\n")
	data := make([]byte, 0, len(contextIDZero)+len(p))
	data = append(data, contextIDZero...)
	data = append(data, p...)
	return len(p), c.str.SendDatagram(data)
}

func (c *proxiedConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr net.Addr, err error) {
	print("Read\n")
start:
	c.deadlineMx.Lock()
	ctx := c.readCtx
	c.deadlineMx.Unlock()

	data, err := c.str.ReceiveDatagram(ctx)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			return 0, 0, 0, nil, err
		}
		c.deadlineMx.Lock()
		restart := time.Now().Before(c.deadline)
		c.deadlineMx.Unlock()
		if restart {
			goto start
		}
		return 0, 0, 0, nil, os.ErrDeadlineExceeded
	}

	// Parse the QUIC Datagram Header (Context ID)
	contextID, nHeader, err := quicvarint.Parse(data)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("masque: malformed datagram: %w", err)
	}

	// ---------------------------------------------------------
	// 1. Prepare OOB Parameters
	// ---------------------------------------------------------
	var layer int
	var typeVal int
	// ECN/TOS is usually a single byte, but CMSG alignment often requires 4 bytes padding
	const dataLen = 1

	// Calculate required space including header alignment
	reqLen := unix.CmsgSpace(dataLen)

	if udpAddr, ok := c.LocalAddr().(*net.UDPAddr); ok && udpAddr.IP.To4() == nil {
		layer = unix.IPPROTO_IPV6
		typeVal = unix.IPV6_TCLASS
	} else {
		layer = unix.IPPROTO_IP
		typeVal = unix.IP_TOS
	}
	print(contextID)
	// Map ContextID to ECN value
	tosByte := byte(contextID & 0x03) // Safety mask, assuming ID maps directly to ECN
	//print(tosByte)

	// ---------------------------------------------------------
	// 2. Write to the EXISTING oob slice (Do not use make!)
	// ---------------------------------------------------------
	oobn = 0 // Default return value if we fail to write OOB

	// Only write OOB if the caller provided enough buffer space
	if len(oob) >= reqLen {
		// Create the Cmsghdr at the start of the buffer
		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		cmsghdr.Level = int32(layer)
		cmsghdr.Type = int32(typeVal)
		cmsghdr.SetLen(unix.CmsgLen(dataLen))

		// Calculate offset to data: Start of buffer + Header Length
		// Standard way to get pointer to data section
		dataPtr := uintptr(unsafe.Pointer(&oob[0])) + uintptr(unix.CmsgLen(0))

		// Write the single byte of TOS data
		*(*byte)(unsafe.Pointer(dataPtr)) = tosByte
		print("T")

		oobn = reqLen
	}

	// ---------------------------------------------------------
	// 3. Return correct types
	// ---------------------------------------------------------
	// Return values:
	// n (payload size), oobn (oob size), flags (0), addr, err
	// IMPORTANT: Cast c.remoteAddr to *net.UDPAddr so quic-go recognizes this method
	return copy(b, data[nHeader:]), oobn, 0, c.remoteAddr.(*net.UDPAddr), nil
}

func (c *proxiedConn) WriteMsgUDP(b, oob []byte, _ net.Addr) (n, oobn int, err error) {
	print("Write\n")
	// Default to Context ID 0 (Non-ECT) if no OOB is provided
	var ecn byte

	// 1. Parse OOB for ECN (TOS/Traffic Class)
	if len(oob) > 0 {
		msgs, err := unix.ParseSocketControlMessage(oob)
		if err != nil {
			return 0, 0, fmt.Errorf("masque: failed to parse oob: %w", err)
		}
		for _, msg := range msgs {
			// Check for IPv4 TOS or IPv6 Traffic Class
			if (msg.Header.Level == unix.IPPROTO_IP && msg.Header.Type == unix.IP_TOS) ||
				(msg.Header.Level == unix.IPPROTO_IPV6 && msg.Header.Type == unix.IPV6_TCLASS) {
				if len(msg.Data) > 0 {
					// Extract ECN (last 2 bits)
					ecn = msg.Data[0] & 0x03
				}
				break
			}
		}
	}

	// 2. Map ECN (0-3) directly to Context ID (0-3)
	// We assume the same 1:1 mapping as used in ReadMsgUDP.
	// 0x00 -> Non-ECT, 0x01 -> ECT(1), 0x02 -> ECT(0), 0x03 -> CE

	// 3. Construct Datagram: [ContextID Varint] + [Payload]
	// Note: Context IDs 0-3 are single-byte varints in QUIC, matching their value.
	data := make([]byte, 0, 1+len(b))
	data = quicvarint.Append(data, uint64(ecn))
	data = append(data, b...)

	// 4. Send
	if err := c.str.SendDatagram(data); err != nil {
		return 0, 0, err
	}

	return len(b), len(oob), nil
}

// ReadFromUDP is a required method for quic-go to recognize this as a UDPConn.
// It wraps ReadMsgUDP but ignores the OOB data.
func (c *proxiedConn) ReadFromUDP(b []byte) (n int, addr net.Addr, err error) {
	n, _, _, addr, err = c.ReadMsgUDP(b, nil)
	return
}

// WriteToUDP is a required method for quic-go to recognize this as a UDPConn.
// It wraps WriteMsgUDP with no OOB data.
func (c *proxiedConn) WriteToUDP(b []byte, addr net.Addr) (int, error) {
	n, _, err := c.WriteMsgUDP(b, nil, addr)
	return n, err
}

// SetReadBuffer is called by quic-go to optimize OS buffers.
// Since this is a proxy, we stub it to satisfy the interface.
func (c *proxiedConn) SetReadBuffer(bytes int) error {
	return nil
}

// SetWriteBuffer is called by quic-go to optimize OS buffers.
// Since this is a proxy, we stub it to satisfy the interface.
func (c *proxiedConn) SetWriteBuffer(bytes int) error {
	return nil
}

func (c *proxiedConn) Close() error {
	c.closed.Store(true)
	c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	err := c.str.Close()
	<-c.readDone
	c.readCtxCancel()
	c.deadlineMx.Lock()
	if c.readDeadlineTimer != nil {
		c.readDeadlineTimer.Stop()
	}
	c.deadlineMx.Unlock()
	return err
}

func (c *proxiedConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *proxiedConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *proxiedConn) SetDeadline(t time.Time) error {
	_ = c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}

func (c *proxiedConn) SetReadDeadline(t time.Time) error {
	c.deadlineMx.Lock()
	defer c.deadlineMx.Unlock()

	oldDeadline := c.deadline
	c.deadline = t
	now := time.Now()
	// Stop the timer.
	if t.IsZero() {
		if c.readDeadlineTimer != nil && !c.readDeadlineTimer.Stop() {
			<-c.readDeadlineTimer.C
		}

		return nil
	}
	// If the deadline already expired, cancel immediately.
	if !t.After(now) {
		c.readCtxCancel()
		return nil
	}
	deadline := t.Sub(now)
	// if we already have a timer, reset it
	if c.readDeadlineTimer != nil {
		// if that timer expired, create a new one
		if now.Before(oldDeadline) {
			c.readCtxCancel() // the old context might already have been cancelled, but that's not guaranteed
			c.readCtx, c.readCtxCancel = context.WithCancel(context.Background())
		}
		c.readDeadlineTimer.Reset(deadline)
	} else { // this is the first time the timer is set
		c.readDeadlineTimer = time.AfterFunc(deadline, func() {
			c.deadlineMx.Lock()
			defer c.deadlineMx.Unlock()
			if !c.deadline.IsZero() && c.deadline.Before(time.Now()) {
				c.readCtxCancel()
			}
		})
	}
	return nil
}

func (c *proxiedConn) SetWriteDeadline(time.Time) error {
	// TODO(#22): This is currently blocked on a change in quic-go's API.
	return nil
}

func skipCapsules(str quicvarint.Reader) error {
	for {
		ct, r, err := http3.ParseCapsule(str)
		if err != nil {
			return err
		}
		log.Printf("skipping capsule of type %d", ct)
		if _, err := io.Copy(io.Discard, r); err != nil {
			return err
		}
	}

}

type noopRawConn struct{}

func (noopRawConn) Control(f func(fd uintptr)) error {
	// We return nil to pretend that any socket option set via Control (like ECN) succeeded.
	// We do NOT call f() because we don't have a real file descriptor,
	// and calling it with 0 (stdin) would be dangerous.
	return nil
}

func (noopRawConn) Read(f func(fd uintptr) (done bool)) error {
	return syscall.EOPNOTSUPP
}

func (noopRawConn) Write(f func(fd uintptr) (done bool)) error {
	return syscall.EOPNOTSUPP
}

// var _ quic.OOBCapablePacketConn = &proxiedConn{}
func (c *proxiedConn) Read(b []byte) (int, error) {
	n, _, _, _, err := c.ReadMsgUDP(b, nil)
	return n, err
}

// Write implements the net.Conn interface.
func (c *proxiedConn) Write(b []byte) (int, error) {
	// We pass nil for the address because WriteMsgUDP ignores it for connected/proxied sockets anyway.
	n, _, err := c.WriteMsgUDP(b, nil, nil)
	return n, err
}
