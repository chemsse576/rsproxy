package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
)

var version = "1.1.0"

func main() {
	log.SetFlags(log.Ltime)

	mode := flag.String("mode", "", "Mode: 'server' or 'client'")

	agentAddr := flag.String("agent", ":8443", "[server] Listen address for agent connections")
	socksAddr := flag.String("socks", "127.0.0.1:1080", "[server] SOCKS5 listen address")
	certFile := flag.String("cert", "", "[server] TLS certificate file (auto-generated if empty)")
	keyFile := flag.String("key", "", "[server] TLS key file (auto-generated if empty)")

	connectAddr := flag.String("connect", "", "[client] Server address (host:port)")
	insecure := flag.Bool("insecure", false, "[client] Skip TLS certificate verification")
	retry := flag.Int("retry", 5, "[client] Reconnect delay in seconds")

	noTLS := flag.Bool("no-tls", false, "Disable TLS (plain TCP, use only on trusted networks)")
	password := flag.String("pass", "", "Authentication password (required)")
	verbose := flag.Bool("v", false, "Verbose logging")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
  ┬─┐┌─┐┌─┐┬─┐┌─┐─┐ ┬┬ ┬
  ├┬┘└─┐├─┘├┬┘│ │┌┴┬┘└┬┘
  ┴└─└─┘┴  ┴└─└─┘┴ └─ ┴  v%s
  Reverse SOCKS5 Proxy

Usage:
  Server: rsproxy -mode server -pass <password> [-agent :8443] [-socks 127.0.0.1:1080]
  Client: rsproxy -mode client -connect <host:port> -pass <password> [-insecure]

Flags:
`, version)
		flag.PrintDefaults()
	}
	flag.Parse()

	if *password == "" {
		fmt.Fprintln(os.Stderr, "[!] -pass is required")
		flag.Usage()
		os.Exit(1)
	}

	switch *mode {
	case "server":
		fmt.Fprintf(os.Stderr, "\n  rsproxy v%s - server mode\n\n", version)
		var tlsCfg *tls.Config
		if !*noTLS {
			var err error
			if *certFile != "" && *keyFile != "" {
				cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
				if err != nil {
					log.Fatalf("[!] Failed to load TLS keypair: %v", err)
				}
				tlsCfg = &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
				}
			} else {
				tlsCfg, err = generateTLSConfig()
				if err != nil {
					log.Fatalf("[!] Failed to generate TLS config: %v", err)
				}
				log.Println("[*] Using auto-generated self-signed certificate")
			}
		} else {
			log.Println("[!] TLS DISABLED - traffic is NOT encrypted")
		}
		runServer(*agentAddr, *socksAddr, *password, tlsCfg, *verbose)

	case "client":
		fmt.Fprintf(os.Stderr, "\n  rsproxy v%s - client mode\n\n", version)
		if *connectAddr == "" {
			fmt.Fprintln(os.Stderr, "[!] -connect is required in client mode")
			os.Exit(1)
		}
		var tlsCfg *tls.Config
		if !*noTLS {
			tlsCfg = &tls.Config{
				InsecureSkipVerify: *insecure,
				MinVersion:         tls.VersionTLS12,
			}
		} else {
			log.Println("[!] TLS DISABLED - traffic is NOT encrypted")
		}
		runClient(*connectAddr, *password, tlsCfg, *retry, *verbose)

	default:
		fmt.Fprintln(os.Stderr, "[!] -mode must be 'server' or 'client'")
		flag.Usage()
		os.Exit(1)
	}
}
