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

type ECNState struct {
	Enabled       bool
	ContextIdECT0 uint64
	ContextIdECT1 uint64
	ContextIdCE   uint64
}

var (
	_ http3Stream = &http3.Stream{}
	_ http3Stream = &http3.RequestStream{}
)

type Conn struct {
	str        http3Stream
	localAddr  net.Addr
	remoteAddr net.Addr
	closeConn  func() error
	ecn        ECNState

	closed   atomic.Bool // set when Close is called
	readDone chan struct{}

	deadlineMx        sync.Mutex
	readCtx           context.Context
	readCtxCancel     context.CancelFunc
	deadline          time.Time
	readDeadlineTimer *time.Timer
}

var _ net.PacketConn = &Conn{}

// closeConn is only used for QUIC connections dialed by [Transport.Dial].
// It is nil for connections created through [Transport.NewClientConn]; callers close those QUIC connections themselves.
func newProxiedConn(str http3Stream, local, remote net.Addr, closeConn func() error, ecn ECNState) *Conn {
	c := &Conn{
		str:        str,
		localAddr:  local,
		remoteAddr: remote,
		closeConn:  closeConn,
		readDone:   make(chan struct{}),
		ecn:        ecn,
	}
	c.readCtx, c.readCtxCancel = context.WithCancel(context.Background())
	go func() {
		defer close(c.readDone)
		if err := skipCapsules(str); err != io.EOF && !c.closed.Load() {
			log.Printf("reading from request stream failed: %v", err)
		}
		str.Close()
	}()
	return c
}

func (c *Conn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
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
func (c *Conn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	data := make([]byte, 0, len(contextIDZero)+len(p))
	data = append(data, contextIDZero...)
	data = append(data, p...)
	return len(p), c.str.SendDatagram(data)
}

func (c *Conn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr net.Addr, err error) {
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

	//Setup OOB
	var layer int
	var typeVal int
	const dataLen = 1
	reqLen := unix.CmsgSpace(dataLen)

	//IPv4
	if udpAddr, ok := c.LocalAddr().(*net.UDPAddr); ok && udpAddr.IP.To4() == nil {
		layer = unix.IPPROTO_IPV6
		typeVal = unix.IPV6_TCLASS
	} else { //IPv6
		layer = unix.IPPROTO_IP
		typeVal = unix.IP_TOS
	}

	//Map ContextID <-> ECN
	tosByte := byte(0)
	if c.ecn.Enabled {
		switch contextID {
		case 0:
			tosByte = byte(0)
		case c.ecn.ContextIdECT1:
			tosByte = byte(1)
		case c.ecn.ContextIdECT0:
			tosByte = byte(2)
		case c.ecn.ContextIdCE:
			tosByte = byte(3)
		default:
			goto start
		}
	} else {
		if contextID != 0 {
			goto start
		}
	}

	//Write tosByte into provided oob
	oobn = 0

	if len(oob) >= reqLen {
		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		cmsghdr.Level = int32(layer)
		cmsghdr.Type = int32(typeVal)
		cmsghdr.SetLen(unix.CmsgLen(dataLen))
		oob[unix.CmsgLen(0)] = tosByte

		oobn = reqLen
	}
	//Retun Msg + OOB
	return copy(b, data[nHeader:]), oobn, 0, c.remoteAddr, nil
}

func (c *Conn) WriteMsgUDP(b, oob []byte, _ net.Addr) (n, oobn int, err error) {
	var ecn byte

	// Parse OOB for ECN
	if len(oob) > 0 {
		msgs, err := unix.ParseSocketControlMessage(oob)
		if err != nil {
			return 0, 0, fmt.Errorf("masque: failed to parse oob: %w", err)
		}
		for _, msg := range msgs {
			// Check for IPv4 TOS or IPv6 Traffic Class.
			// The oob may come straight from a socket read: macOS reports the received TOS as IP_RECVTOS, Linux as IP_TOS.
			if (msg.Header.Level == unix.IPPROTO_IP && (msg.Header.Type == unix.IP_TOS || msg.Header.Type == unix.IP_RECVTOS)) ||
				(msg.Header.Level == unix.IPPROTO_IPV6 && (msg.Header.Type == unix.IPV6_TCLASS || msg.Header.Type == unix.IPV6_RECVTCLASS)) {
				if len(msg.Data) > 0 {
					// Extract ECN
					ecn = msg.Data[0] & 0x03
				}
				break
			}
		}
	}

	//Map ECN <-> ContextID
	var contextId uint64 = 0
	if c.ecn.Enabled {
		switch ecn {
		case 0:
			contextId = 0
		case 1:
			contextId = c.ecn.ContextIdECT1
		case 2:
			contextId = c.ecn.ContextIdECT0
		case 3:
			contextId = c.ecn.ContextIdCE
		}
	}
	cId := quicvarint.Append([]byte{}, contextId)

	//Construct Datagram
	data := make([]byte, 0, len(cId)+len(b))
	data = append(data, cId...)
	data = append(data, b...)

	//  Send
	if err := c.str.SendDatagram(data); err != nil {
		return 0, 0, err
	}

	return len(b), len(oob), nil
}

func (c *Conn) ReadFromUDP(b []byte) (n int, addr net.Addr, err error) {
	n, _, _, addr, err = c.ReadMsgUDP(b, nil)
	return
}

func (c *Conn) WriteToUDP(b []byte, addr net.Addr) (int, error) {
	n, _, err := c.WriteMsgUDP(b, nil, addr)
	return n, err
}

func (c *Conn) SetReadBuffer(bytes int) error {
	return nil
}

func (c *Conn) SetWriteBuffer(bytes int) error {
	return nil
}

func (c *Conn) Close() error {
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
	if c.closeConn != nil {
		return errors.Join(err, c.closeConn())
	}
	return err
}

func (c *Conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *Conn) SetDeadline(t time.Time) error {
	_ = c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
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

func (c *Conn) SetWriteDeadline(time.Time) error {
	// TODO(#22): This is currently blocked on a change in quic-go's API.
	return nil
}

func skipCapsules(str io.Reader) error {
	parser := http3.NewCapsuleParser(str)
	for {
		ct, r, err := parser.Next()
		if err != nil {
			return err
		}
		log.Printf("skipping capsule of type %d", ct)
		if err := r.Discard(); err != nil {
			return err
		}
	}
}

func (c *Conn) Read(b []byte) (int, error) {
	n, _, _, _, err := c.ReadMsgUDP(b, nil)
	return n, err
}

func (c *Conn) Write(b []byte) (int, error) {
	n, _, err := c.WriteMsgUDP(b, nil, nil)
	return n, err
}
