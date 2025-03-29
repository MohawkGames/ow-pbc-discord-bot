package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/bwmarrin/discordgo"
	"github.com/joho/godotenv"
)

const (
	CommandName = "owturn"
	SubCmdStart = "start"
	SubCmdIam   = "iam"
)

var (
	botToken       string
	appID          string
	guildID        string
	baseURL        string
	certPath       string
	certKeyPath    string
	discordSession *discordgo.Session

	config      = LoadConfig("config.json")
	configMutex sync.RWMutex

	debug bool
)

type GameInfo struct {
	ChannelID string `json:"channelId"`
	Token     string `json:"token"`
}

type Config struct {
	UserMap        map[string]string   `json:"userMap"`
	GameChannelMap map[string]GameInfo `json:"gameChannelMap"`
}

func NewConfig() *Config {
	return &Config{
		UserMap:        make(map[string]string),
		GameChannelMap: make(map[string]GameInfo),
	}
}

func (c *Config) Save(filename string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, data, 0644)
}

func LoadConfig(filename string) *Config {
	c := NewConfig()
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Printf("[WARN] Could not read config file: %v. Using default config.", err)
		return c
	}
	if err := json.Unmarshal(data, c); err != nil {
		log.Printf("[WARN] Error parsing config file: %v. Using default config.", err)
		return c
	}
	return c
}

// This is the notification OW sends when a turn has been played
type TurnNotification struct {
	Game   string `json:"game"`
	Turn   int    `json:"turn"`
	Player string `json:"player"`
	Nation string `json:"nation"`
}

func loadEnv() {
	botToken = os.Getenv("DISCORD_BOT_TOKEN")
	appID = os.Getenv("DISCORD_APP_ID")
	guildID = os.Getenv("DISCORD_GUILD_ID")
	baseURL = os.Getenv("BASE_URL")
	certPath = os.Getenv("CERT_PEM")
	certKeyPath = os.Getenv("CERT_KEY")

	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	debug = os.Getenv("DEBUG") == "true" || os.Getenv("DEBUG") == "1"
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Printf("[INFO] No .env file, relying on OS environment")
	}
	loadEnv()
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		log.Printf("[WARN] Could not parse BASE_URL (%s), defaulting to :8080", baseURL)
		parsedURL = &url.URL{Host: "localhost:8080"}
	}
	_, port, err := net.SplitHostPort(parsedURL.Host)
	if err != nil || port == "" {
		port = "8080"
	}

	discordSession, err = discordgo.New("Bot " + botToken)
	if err != nil {
		log.Fatalf("[ERROR] Error creating Discord session: %v", err)
	}

	discordSession.AddHandlerOnce(ready)
	err = discordSession.Open()
	if err != nil {
		log.Fatalf("[ERROR] Error opening Discord connection: %v", err)
	}
	defer discordSession.Close()

	registerCommands(discordSession)

	http.HandleFunc("/turn", turnHandler)
	fs := http.FileServer(http.Dir("./www"))
	http.Handle("/", fs)

	srv := &http.Server{Addr: ":" + port}

	go func() {
		if certPath == "" {
			log.Printf("[INFO] HTTP server is running on :%s", port)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[ERROR] HTTP server error: %v", err)
			}
		} else {
			log.Printf("[INFO] HTTPS server is running on :%s", port)
			if err := srv.ListenAndServeTLS(certPath, certKeyPath); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[ERROR] HTTPS server error: %v", err)
			}
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Printf("[INFO] Shutting down...")

	if err := srv.Shutdown(context.Background()); err != nil {
		log.Printf("[ERROR] HTTP server Shutdown: %v", err)
	}

	log.Printf("[INFO] Shutdown complete.")
}

func ready(s *discordgo.Session, event *discordgo.Ready) {
	log.Printf("[INFO] Logged in as: %v#%v", s.State.User.Username, s.State.User.Discriminator)
}

func generateToken() (string, error) {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func registerCommands(s *discordgo.Session) {
	commands := []*discordgo.ApplicationCommand{
		{
			Name:        CommandName,
			Description: "Old World PBC notifier",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Name:        SubCmdStart,
					Description: "Start turn notifications for a specific game",
					Options: []*discordgo.ApplicationCommandOption{
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "game",
							Description: "Game identifier",
							Required:    true,
						},
					},
				},
				{
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Name:        SubCmdIam,
					Description: "Associate your in-game name",
					Options: []*discordgo.ApplicationCommandOption{
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "owname",
							Description: "Name in Old World",
							Required:    true,
						},
					},
				},
			},
		},
	}

	for _, cmd := range commands {
		_, err := s.ApplicationCommandCreate(appID, guildID, cmd)
		if err != nil {
			log.Printf("[ERROR] Cannot create '%v' command: %v", cmd.Name, err)
		}
	}

	s.AddHandler(func(s *discordgo.Session, i *discordgo.InteractionCreate) {
		if i.Type != discordgo.InteractionApplicationCommand {
			return
		}

		if i.ApplicationCommandData().Name == CommandName {
			subCmd := i.ApplicationCommandData().Options[0]
			switch subCmd.Name {
			case SubCmdStart:
				game := subCmd.Options[0].StringValue()
				channelID := i.ChannelID

				token, err := generateToken()
				if err != nil {
					log.Printf("[ERROR] Failed to generate token: %v", err)
					s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
						Type: discordgo.InteractionResponseChannelMessageWithSource,
						Data: &discordgo.InteractionResponseData{
							Content: "Failed to generate token.",
						},
					})
					return
				}

				configMutex.Lock()
				config.GameChannelMap[game] = GameInfo{
					ChannelID: channelID,
					Token:     token,
				}
				if err := config.Save("config.json"); err != nil {
					log.Printf("[ERROR] Error saving config: %v", err)
				}
				configMutex.Unlock()

				fullURL := fmt.Sprintf("%s/turn?token=%s", baseURL, token)

				s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: fmt.Sprintf("Notifications for game '%s' will be posted here.\nThe host should set the notification URL to: %s", game, fullURL),
					},
				})
			case SubCmdIam:
				playerName := subCmd.Options[0].StringValue()
				configMutex.Lock()
				config.UserMap[playerName] = i.Member.User.ID
				if err := config.Save("config.json"); err != nil {
					log.Printf("[ERROR] Error saving config: %v", err)
				}
				configMutex.Unlock()

				s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: fmt.Sprintf("I now remember you as '%s'", playerName),
					},
				})
			}
		}
	})
}

func turnHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	tokenQuery := r.URL.Query().Get("token")
	if tokenQuery == "" {
		http.Error(w, "Token is required", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Could not read body", http.StatusInternalServerError)
		return
	}

	if debug {
		log.Printf("[DEBUG] Received request body: %s", string(body))
	}

	var note TurnNotification
	if err := json.Unmarshal(body, &note); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	configMutex.RLock()
	gameInfo, gameExists := config.GameChannelMap[note.Game]
	discordID, userExists := config.UserMap[note.Player]
	configMutex.RUnlock()

	if !gameExists || gameInfo.Token != tokenQuery {
		http.Error(w, "Invalid token for game", http.StatusForbidden)
		return
	}

	msg := fmt.Sprintf("Game %s, Turn %d", note.Game, note.Turn)
	if userExists {
		userMsg := fmt.Sprintf("It is now <@%s>'s turn.", discordID)
		msg = fmt.Sprintf("%s\n%s", msg, userMsg)
	} else {
		msg = fmt.Sprintf("%s\nIt is now %s's turn.", msg, note.Player)
	}
	log.Printf("[INFO] Notification: %s", msg)
	log.Printf("[INFO] Sending to channel: %s", gameInfo.ChannelID)

	_, err = discordSession.ChannelMessageSend(gameInfo.ChannelID, msg)
	if err != nil {
		log.Printf("[ERROR] Error sending message: %v", err)
	}
	// If we want to DM?
	/*
		if userExists {
			dm, err := discordSession.UserChannelCreate(discordID)
			if err != nil {
				log.Printf("[ERROR] Error getting DM channel: %v", err)
			}
			_, err = session.ChannelMessageSend(dm.ID, msg)
			if err != nil {
				log.Printf("[ERROR] Error sending DM: %v", err)
			}

		}*/

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
