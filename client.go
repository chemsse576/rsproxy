package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

func runClient(addr, password string, tlsCfg *tls.Config, retryDelay int, verbose bool) {
	for {
		err := clientSession(addr, password, tlsCfg, verbose)
		if err != nil {
			log.Printf("[!] %v", err)
		}
		log.Printf("[*] Reconnecting in %ds...", retryDelay)
		time.Sleep(time.Duration(retryDelay) * time.Second)
	}
}

func clientSession(addr, password string, tlsCfg *tls.Config, verbose bool) error {
	log.Printf("[*] Connecting to %s...", addr)

	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	var conn net.Conn
	var err error
	if tlsCfg != nil {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("dial TLS: %w (if server uses -no-tls, add -no-tls on client too)", err)
		}
		if verbose {
			state := conn.(*tls.Conn).ConnectionState()
			log.Printf("[*] TLS OK: version=0x%04x cipher=0x%04x", state.Version, state.CipherSuite)
		}
	} else {
		conn, err = dialer.Dial("tcp", addr)
		if err != nil {
			return fmt.Errorf("dial: %w", err)
		}
		if verbose {
			log.Printf("[*] Connected (plain TCP)")
		}
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	if _, err := conn.Write(protoMagic); err != nil {
		return fmt.Errorf("protocol write: %w", err)
	}

	magicResp := make([]byte, 4)
	if _, err := io.ReadFull(conn, magicResp); err != nil {
		return fmt.Errorf("protocol read: %w (TLS mismatch? both sides must use the same -no-tls setting)", err)
	}
	if magicResp[0] != 'R' || magicResp[1] != 'S' || magicResp[2] != 'P' || magicResp[3] != 0x01 {
		return fmt.Errorf("invalid server response (got %x). Wrong server or TLS mismatch", magicResp)
	}

	if verbose {
		log.Printf("[*] Protocol handshake OK")
	}

	pass := []byte(password)
	hdr := make([]byte, 2+len(pass))
	binary.BigEndian.PutUint16(hdr[:2], uint16(len(pass)))
	copy(hdr[2:], pass)
	if _, err := conn.Write(hdr); err != nil {
		return fmt.Errorf("auth write: %w", err)
	}

	if verbose {
		log.Printf("[*] Auth sent, waiting for response...")
	}

	st := make([]byte, 1)
	if _, err := io.ReadFull(conn, st); err != nil {
		return fmt.Errorf("auth read: %w", err)
	}
	if st[0] != 0x00 {
		return fmt.Errorf("authentication rejected by server (wrong password)")
	}

	conn.SetDeadline(time.Time{})
	log.Printf("[+] Authenticated to %s", addr)

	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.ConnectionWriteTimeout = 10 * time.Second
	session, err := yamux.Client(conn, cfg)
	if err != nil {
		return fmt.Errorf("yamux: %w", err)
	}
	defer session.Close()

	for {
		stream, err := session.Accept()
		if err != nil {
			return fmt.Errorf("session closed: %w", err)
		}
		go handleTunnel(stream, verbose)
	}
}

func handleTunnel(stream net.Conn, verbose bool) {
	defer stream.Close()

	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(stream, typeBuf); err != nil {
		return
	}

	var host string
	switch typeBuf[0] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(stream, b); err != nil {
			return
		}
		host = net.IP(b).String()

	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(stream, lb); err != nil {
			return
		}
		d := make([]byte, lb[0])
		if _, err := io.ReadFull(stream, d); err != nil {
			return
		}
		host = string(d)

	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(stream, b); err != nil {
			return
		}
		host = net.IP(b).String()

	default:
		stream.Write([]byte{0x01})
		return
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(stream, pb); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb)
	target := fmt.Sprintf("%s:%d", host, port)

	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		stream.Write([]byte{0x01})
		if verbose {
			log.Printf("[-] Connect failed: %s: %v", target, err)
		}
		return
	}
	defer targetConn.Close()

	stream.Write([]byte{0x00})

	if verbose {
		log.Printf("[>] %s", target)
	}

	relay(stream, targetConn)

	if verbose {
		log.Printf("[<] %s", target)
	}
}
