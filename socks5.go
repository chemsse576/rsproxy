package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

func socks5Handshake(conn net.Conn) (target string, addrType byte, addrBytes []byte, port uint16, err error) {
	buf := make([]byte, 256)

	if _, err = io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		err = fmt.Errorf("unsupported SOCKS version: %d", buf[0])
		return
	}
	nMethods := int(buf[1])
	if _, err = io.ReadFull(conn, buf[:nMethods]); err != nil {
		return
	}

	conn.Write([]byte{0x05, 0x00})

	if _, err = io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		err = fmt.Errorf("unsupported SOCKS version in request: %d", buf[0])
		return
	}
	if buf[1] != 0x01 {
		socks5Reply(conn, 0x07)
		err = fmt.Errorf("unsupported command: %d", buf[1])
		return
	}

	addrType = buf[3]

	switch addrType {
	case 0x01:
		addrBytes = make([]byte, 4)
		if _, err = io.ReadFull(conn, addrBytes); err != nil {
			return
		}
		target = net.IP(addrBytes).String()

	case 0x03:
		if _, err = io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		dLen := buf[0]
		domain := make([]byte, dLen)
		if _, err = io.ReadFull(conn, domain); err != nil {
			return
		}
		addrBytes = append([]byte{dLen}, domain...)
		target = string(domain)

	case 0x04:
		addrBytes = make([]byte, 16)
		if _, err = io.ReadFull(conn, addrBytes); err != nil {
			return
		}
		target = net.IP(addrBytes).String()

	default:
		socks5Reply(conn, 0x08)
		err = fmt.Errorf("unsupported address type: %d", addrType)
		return
	}

	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(portBuf)
	target = fmt.Sprintf("%s:%d", target, port)
	return
}

func socks5Reply(conn net.Conn, status byte) {
	conn.Write([]byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func relay(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	cp := func(dst io.WriteCloser, src io.Reader) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	a.Close()
	b.Close()
	<-done
}
