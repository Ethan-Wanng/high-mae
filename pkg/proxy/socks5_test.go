package proxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"wing/pkg/common"
	"wing/pkg/routing"
	"wing/protocol"
)

func TestHandleSOCKS5DirectInProcessRelayAndUDPReject(t *testing.T) {
	oldClient := common.GetActiveClient()
	oldMode := common.GetProxyMode()
	oldTun := common.GetTunModeOn()
	oldRules := routing.RuleGroups
	oldPrivacy := common.PrivacyMode
	common.SetActiveClient(protocol.Node{}, "", nil)
	common.SetProxyMode("Rule")
	common.SetTunModeOn(false)
	common.PrivacyMode = true
	t.Cleanup(func() {
		common.SetActiveClient(protocol.Node{}, "", oldClient)
		common.SetProxyMode(oldMode)
		common.SetTunModeOn(oldTun)
		routing.RuleGroups = oldRules
		common.PrivacyMode = oldPrivacy
	})

	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echoListener.Close()
	go func() {
		for {
			c, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	t.Run("tcp_connect_direct_relay", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			handleSOCKS5(serverConn)
		}()

		// Greeting: VER=5, NMETHODS=1, NO AUTH=0
		if _, err := clientConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			t.Fatalf("write greeting: %v", err)
		}
		var methodReply [2]byte
		if _, err := io.ReadFull(clientConn, methodReply[:]); err != nil {
			t.Fatalf("read method reply: %v", err)
		}
		if !bytes.Equal(methodReply[:], []byte{0x05, 0x00}) {
			t.Fatalf("method reply = %v, want [5 0]", methodReply)
		}

		addr := echoListener.Addr().(*net.TCPAddr)
		var req []byte
		req = append(req, 0x05, 0x01, 0x00, 0x01)
		req = append(req, addr.IP.To4()...)
		var portBuf [2]byte
		binary.BigEndian.PutUint16(portBuf[:], uint16(addr.Port))
		req = append(req, portBuf[:]...)
		if _, err := clientConn.Write(req); err != nil {
			t.Fatalf("write CONNECT %s: %v", strconv.Itoa(addr.Port), err)
		}

		var connectReply [10]byte
		if _, err := io.ReadFull(clientConn, connectReply[:]); err != nil {
			t.Fatalf("read connect reply: %v", err)
		}
		if connectReply[1] != 0x00 {
			t.Fatalf("SOCKS5 connect status = %d, want 0", connectReply[1])
		}

		payload := []byte("wing-android-direct-socks5-echo")
		if _, err := clientConn.Write(payload); err != nil {
			t.Fatalf("write echo payload: %v", err)
		}
		echoed := make([]byte, len(payload))
		if _, err := io.ReadFull(clientConn, echoed); err != nil {
			t.Fatalf("read echo payload: %v", err)
		}
		if !bytes.Equal(echoed, payload) {
			t.Fatalf("echoed = %q, want %q", echoed, payload)
		}

		_ = clientConn.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("handleSOCKS5 did not return cleanly after client close")
		}
	})

	t.Run("udp_associate_rejected", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			handleSOCKS5(serverConn)
		}()

		_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00})
		var methodReply [2]byte
		_, _ = io.ReadFull(clientConn, methodReply[:])

		_, _ = clientConn.Write([]byte{0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0, 53})
		var reply [10]byte
		if _, err := io.ReadFull(clientConn, reply[:]); err != nil {
			t.Fatalf("read UDP reject reply: %v", err)
		}
		if reply[1] != 0x07 {
			t.Fatalf("UDP associate reply status = %d, want 0x07", reply[1])
		}
		_ = clientConn.Close()
		<-done
	})
}
