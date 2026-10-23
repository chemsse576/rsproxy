package main

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
)

var protoMagic = []byte{'R', 'S', 'P', 0x01}

type server struct {
	agentAddr string
	socksAddr string
	password  string
	tlsCfg    *tls.Config
	verbose   bool
	session   *yamux.Session
	mu        sync.RWMutex
	connID    atomic.Int64
}

func runServer(agentAddr, socksAddr, password string, tlsCfg *tls.Config, verbose bool) {
	s := &server{
		agentAddr: agentAddr,
		socksAddr: socksAddr,
		password:  password,
		tlsCfg:    tlsCfg,
		verbose:   verbose,
	}
	go s.listenAgent()
	s.listenSocks()
}

func (s *server) listenAgent() {
	var ln net.Listener
	var err error
	if s.tlsCfg != nil {
		ln, err = tls.Listen("tcp", s.agentAddr, s.tlsCfg)
	} else {
		ln, err = net.Listen("tcp", s.agentAddr)
	}
	if err != nil {
		log.Fatalf("[!] Agent listen failed on %s: %v", s.agentAddr, err)
	}
	proto := "TLS"
	if s.tlsCfg == nil {
		proto = "plain TCP"
	}
	log.Printf("[*] Agent listener on %s (%s)", s.agentAddr, proto)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[!] Agent accept: %v", err)
			continue
		}
		log.Printf("[*] Agent connection from %s", conn.RemoteAddr())
		go s.handleAgent(conn)
	}
}

func (s *server) handleAgent(conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	if tlsConn, ok := conn.(*tls.Conn); ok {
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("[!] TLS handshake failed from %s: %v (is the client using -no-tls?)", conn.RemoteAddr(), err)
			return
		}
		if s.verbose {
			state := tlsConn.ConnectionState()
			log.Printf("[*] TLS OK: version=0x%04x cipher=0x%04x from %s",
				state.Version, state.CipherSuite, conn.RemoteAddr())
		}
	}

	magic := make([]byte, 4)
	if _, err := io.ReadFull(conn, magic); err != nil {
		log.Printf("[!] Protocol read from %s: %v", conn.RemoteAddr(), err)
		return
	}
	if magic[0] == 0x16 && magic[1] == 0x03 {
		log.Printf("[!] Agent from %s sent TLS ClientHello but server is in plain TCP mode. Add -no-tls on the client or remove it from the server.", conn.RemoteAddr())
		return
	}
	if magic[0] != 'R' || magic[1] != 'S' || magic[2] != 'P' || magic[3] != 0x01 {
		log.Printf("[!] Invalid protocol magic from %s (got %x). TLS mismatch? Both sides must use the same -no-tls setting.", conn.RemoteAddr(), magic)
		return
	}

	if _, err := conn.Write(protoMagic); err != nil {
		log.Printf("[!] Protocol write to %s: %v", conn.RemoteAddr(), err)
		return
	}

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		log.Printf("[!] Auth read (length) from %s: %v", conn.RemoteAddr(), err)
		return
	}
	passLen := binary.BigEndian.Uint16(lenBuf)
	if passLen == 0 || passLen > 1024 {
		log.Printf("[!] Invalid password length %d from %s", passLen, conn.RemoteAddr())
		conn.Write([]byte{0x01})
		return
	}
	passBuf := make([]byte, passLen)
	if _, err := io.ReadFull(conn, passBuf); err != nil {
		log.Printf("[!] Auth read (password) from %s: %v", conn.RemoteAddr(), err)
		return
	}

	if string(passBuf) != s.password {
		conn.Write([]byte{0x01})
		log.Printf("[!] Auth FAILED from %s (wrong password)", conn.RemoteAddr())
		return
	}
	if _, err := conn.Write([]byte{0x00}); err != nil {
		log.Printf("[!] Auth write to %s: %v", conn.RemoteAddr(), err)
		return
	}

	conn.SetDeadline(time.Time{})
	log.Printf("[+] Agent authenticated from %s", conn.RemoteAddr())

	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.ConnectionWriteTimeout = 10 * time.Second
	session, err := yamux.Server(conn, cfg)
	if err != nil {
		log.Printf("[!] Yamux session: %v", err)
		return
	}

	s.mu.Lock()
	old := s.session
	s.session = session
	s.mu.Unlock()
	if old != nil {
		old.Close()
		log.Println("[*] Replaced previous agent session")
	}

	<-session.CloseChan()
	log.Printf("[-] Agent disconnected: %s", conn.RemoteAddr())

	s.mu.Lock()
	if s.session == session {
		s.session = nil
	}
	s.mu.Unlock()
}

func (s *server) listenSocks() {
	ln, err := net.Listen("tcp", s.socksAddr)
	if err != nil {
		log.Fatalf("[!] SOCKS5 listen failed on %s: %v", s.socksAddr, err)
	}
	log.Printf("[*] SOCKS5 listener on %s", s.socksAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[!] SOCKS5 accept: %v", err)
			continue
		}
		go s.handleSocks(conn)
	}
}

func (s *server) handleSocks(conn net.Conn) {
	defer conn.Close()

	target, addrType, addrBytes, port, err := socks5Handshake(conn)
	if err != nil {
		if s.verbose {
			log.Printf("[!] SOCKS5 handshake: %v", err)
		}
		return
	}

	s.mu.RLock()
	sess := s.session
	s.mu.RUnlock()

	if sess == nil {
		socks5Reply(conn, 0x04)
		log.Printf("[!] No agent connected, rejecting %s", target)
		return
	}

	stream, err := sess.Open()
	if err != nil {
		socks5Reply(conn, 0x01)
		log.Printf("[!] Yamux stream open: %v", err)
		return
	}

	req := make([]byte, 0, 1+len(addrBytes)+2)
	req = append(req, addrType)
	req = append(req, addrBytes...)
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, port)
	req = append(req, pb...)

	if _, err := stream.Write(req); err != nil {
		stream.Close()
		socks5Reply(conn, 0x01)
		return
	}

	status := make([]byte, 1)
	if _, err := io.ReadFull(stream, status); err != nil {
		stream.Close()
		socks5Reply(conn, 0x01)
		return
	}
	if status[0] != 0x00 {
		stream.Close()
		socks5Reply(conn, 0x05)
		if s.verbose {
			log.Printf("[-] Agent: connection refused to %s", target)
		}
		return
	}

	socks5Reply(conn, 0x00)

	id := s.connID.Add(1)
	if s.verbose {
		log.Printf("[>] #%d %s", id, target)
	}

	relay(conn, stream)

	if s.verbose {
		log.Printf("[<] #%d %s", id, target)
	}
}
