package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	tgbotapi "github.com/egovorukhin/telebot-api"
	"github.com/gocolly/colly"
	_ "github.com/mattn/go-sqlite3"
	"github.com/ringsaturn/tzf"
	"github.com/robfig/cron/v3"
)

var (
	db       *sql.DB
	botToken string
	chatID   int64
	threadID int
	f        tzf.F
	verbose  bool
	location *time.Location
)

func init() {
	// Define flags for token and chat ID
	flag.StringVar(&botToken, "token", "", "Telegram bot token")
	flag.Int64Var(&chatID, "id", 0, "Telegram chat ID")
	flag.IntVar(&threadID, "thread", 0, "Telegram thread ID")
	flag.BoolVar(&verbose, "v", false, "Enable verbose logging")
	flag.Parse()

	// Check if running in test mode via an environment variable
	if os.Getenv("SKIP_FLAG_CHECK") == "" {
		if botToken == "" || chatID == 0 || threadID == 0 {
			log.Fatal("Bot token, chat ID, and thread ID must be provided as flags.")
		}
	}

	var err error

	f, err = tzf.NewDefaultFinder()
	if err != nil {
		log.Fatal(err)
	}
	location, err = time.LoadLocation("Asia/Jakarta")
	if err != nil {
		log.Fatal("Failed to load Jakarta timezone:", err)
	}
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "ppk.db")
	if err != nil {
		log.Fatal(err)
	}

	query := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE,
		status INTEGER DEFAULT 0
	);`
	_, err = db.Exec(query)
	if err != nil {
		log.Fatal(err)
	}
	// add field strava_name if not exists
	query = `ALTER TABLE users ADD COLUMN strava_name TEXT;`
	_, err = db.Exec(query)
	if err != nil {
		log.Println("Error adding strava_name field:", err)
	}

	query = `ALTER TABLE users ADD COLUMN deleted_at INTEGER;`
	_, err = db.Exec(query)
	if err != nil {
		log.Println("Error adding deleted_at field:", err)
	}
	query = `CREATE INDEX IF NOT EXISTS idx_deleted_at ON users (deleted_at);`
	_, err = db.Exec(query)
	if err != nil {
		log.Println("Error adding deleted_at index:", err)
	}

	query = `CREATE INDEX IF NOT EXISTS idx_username_deleted_at ON users (username, deleted_at);`
	_, err = db.Exec(query)
	if err != nil {
		log.Println("Error adding username_deleted_at index:", err)
	}

	query = `ALTER TABLE users ADD COLUMN strava_id_text TEXT;`
	_, err = db.Exec(query)
	if err != nil {
		log.Println("Error adding strava_id_text field:", err)
	}
	query = `CREATE UNIQUE INDEX IF NOT EXISTS idx_strava_id_text ON users (strava_id_text);`
	_, err = db.Exec(query)
	if err != nil {
		log.Println("Error adding strava_id_text index:", err)
	}

	query = `ALTER TABLE users ADD COLUMN distance NUMERIC NOT NULL DEFAULT 0;`
	_, err = db.Exec(query)
	if err != nil {
		log.Println("Error adding distance field:", err)
	}
}

func resetStatus(ctx context.Context, username string, status int, distance float64) error {
	username = strings.ToLower(username)

	var exists bool
	err := db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE username = ? AND deleted_at IS NULL)", username).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		_, err = db.ExecContext(ctx, "UPDATE users SET status = ? , distance = distance + ? WHERE username = ? AND deleted_at IS NULL", status, distance, username)
	} else {
		_, err = db.ExecContext(ctx, "INSERT INTO users (username, status, distance) VALUES (?, ?, ?)", username, status, distance)
	}

	return err
}

// Add new function to check and notify users with high status
func notifyHighStatusUsers(ctx context.Context, bot *tgbotapi.BotAPI) {
	rows, err := db.QueryContext(ctx, "SELECT username, status FROM users WHERE deleted_at IS NULL ORDER BY status, username")
	if err != nil {
		log.Println("Error querying users:", err)
		return
	}
	defer rows.Close()

	now := time.Now()

	var pemalas []string
	for rows.Next() {
		var username string
		var status int
		if err := rows.Scan(&username, &status); err != nil {
			log.Println("Error scanning username:", err)
			continue
		}

		if status < 3 {
			continue
		}

		// handle old value
		if status < 20 && status >= 3 {
			pemalas = append(pemalas, fmt.Sprintf("@%s: %d hari", username, status))
			continue
		}

		dif := now.Sub(time.Unix(int64(status), 0))

		// check if status is older than 3 days
		if dif.Hours() < 24*3 {
			continue
		}

		days := int(dif.Hours() / 24)
		remainingHours := int(dif.Hours()) % 24
		remainingMinutes := int(dif.Minutes()) % 60

		duration := fmt.Sprintf("%d hari %d jam %d menit", days, remainingHours, remainingMinutes)

		pemalas = append(pemalas, fmt.Sprintf("@%s: %s", username, duration))
	}

	if err = rows.Err(); err != nil {
		log.Println("Error iterating rows:", err)
		return
	}

	if len(pemalas) > 0 {
		message := "🚨 Reminder untuk olahraga!\n\nUser yang belum olahraga 3 hari atau lebih:\n" +
			strings.Join(pemalas, "\n") +
			"\n\nJangan lupa kirim link aktivitas Strava untuk mereset status ya!"
		msg := tgbotapi.NewMessage(chatID, message)
		msg.MessageThreadId = threadID
		_, err := bot.Send(msg)
		if err != nil {
			log.Println("Error sending notification:", err)
		}
		return
	}

	message := "🎉 Selamat! Semua user rajin berolahraga! Pertahankan ya! 💪"
	msg := tgbotapi.NewMessage(chatID, message)
	msg.MessageThreadId = threadID
	_, err = bot.Send(msg)
	if err != nil {
		log.Println("Error sending notification:", err)
	}
}

// Update startDailyIncrementJob to include both cron jobs
func startDailyIncrementJob(ctx context.Context, bot *tgbotapi.BotAPI) *cron.Cron {
	var err error
	location, err = time.LoadLocation("Asia/Jakarta")
	if err != nil {
		log.Fatal("Failed to load Jakarta timezone:", err)
	}

	c := cron.New(cron.WithLocation(location))

	// 8 AM job to notify about high status users
	_, err = c.AddFunc("0 8 * * *", func() {
		notifyHighStatusUsers(ctx, bot)
	})
	if err != nil {
		log.Fatal("Failed to schedule notification cron job:", err)
	}

	// 00:05 AM every monday job to reset distance
	_, err = c.AddFunc("5 0 * * 1", func() {
		_, err = db.ExecContext(ctx, "UPDATE users SET distance = 0 WHERE deleted_at IS NULL")
		if err != nil {
			log.Println("Error resetting distance:", err)
		}
	})
	if err != nil {
		log.Fatal("Failed to schedule distance reset cron job:", err)
	}

	c.Start()
	log.Println("Scheduled daily jobs: increment at 12 AM and notifications at 8 AM Jakarta time.")
	return c
}

// Checks if the user is an admin in the chat
func isAdmin(bot *tgbotapi.BotAPI, chatID int64, userID int64) bool {
	admins, err := bot.GetChatAdministrators(tgbotapi.ChatAdministratorsConfig{
		ChatConfig: tgbotapi.ChatConfig{ChatID: chatID},
	})
	if err != nil {
		log.Println("Error fetching admins:", err)
		return false
	}

	for _, admin := range admins {
		if admin.User.ID == userID {
			return true
		}
	}
	return false
}

// Retrieves the top 10 users ordered by status (descending)
func getTopStats(ctx context.Context) ([]string, error) {
	rows, err := db.QueryContext(ctx, "SELECT username, status FROM users WHERE deleted_at IS NULL ORDER BY status, username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	now := time.Now()

	var stats []string
	for rows.Next() {
		var username string
		var status int
		err := rows.Scan(&username, &status)
		if err != nil {
			return nil, err
		}

		if status < 3 {
			continue
		}

		// handle old value
		if status < 20 && status >= 3 {
			stats = append(stats, fmt.Sprintf("@%s: %d hari", username, status))
			continue
		}

		dif := now.Sub(time.Unix(int64(status), 0))

		// check if status is older than 3 days
		if dif.Hours() < 24*3 {
			continue
		}

		days := int(dif.Hours() / 24)
		remainingHours := int(dif.Hours()) % 24
		remainingMinutes := int(dif.Minutes()) % 60

		duration := fmt.Sprintf("%d hari %d jam %d menit", days, remainingHours, remainingMinutes)

		stats = append(stats, fmt.Sprintf("@%s: %s", username, duration))
	}

	if len(stats) == 0 {
		return []string{"No data available."}, nil
	}

	return stats, nil
}

// Sets the specified user's status to the given value
func setStatusUnix(ctx context.Context, username string, status int) error {
	username = strings.ToLower(username)

	var exists bool
	err := db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE username = ? AND deleted_at IS NULL)", username).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		_, err = db.ExecContext(ctx, "UPDATE users SET status = ? WHERE username = ? AND deleted_at IS NULL", status, username)
	} else {
		_, err = db.ExecContext(ctx, "INSERT INTO users (username, status) VALUES (?, ?)", username, status)
	}

	return err
}

// Deletes the specified user from the database
func deleteUser(ctx context.Context, username string) error {
	username = strings.ToLower(username)
	result, err := db.ExecContext(ctx, "UPDATE users SET deleted_at = ? WHERE username = ? AND deleted_at IS NULL", time.Now().Unix(), username)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("user @%s not found", username)
	}

	return nil
}

func restoreUser(ctx context.Context, username string) error {
	username = strings.ToLower(username)
	result, err := db.ExecContext(ctx, "UPDATE users SET deleted_at = NULL WHERE username = ?", username)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("user @%s not found", username)
	}

	return nil
}

// Add new function to ensure user exists in database
func ensureUserExists(ctx context.Context, username string) error {
	if username == "" {
		return nil // Skip if username is empty
	}

	username = strings.ToLower(username)
	var exists bool
	err := db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE username = ? AND deleted_at IS NULL)", username).Scan(&exists)
	if err != nil {
		return err
	}

	nowSub3Days := time.Now().Add(3 * -24 * time.Hour).Unix()

	if !exists {
		_, err = db.ExecContext(ctx, "INSERT INTO users (username, status) VALUES (?, ?)", username, nowSub3Days)
		if err != nil {
			return err
		}
		log.Printf("Added new user @%s to database", username)
	}
	return nil
}

func setStravaName(ctx context.Context, username string, stravaName string) error {
	username = strings.ToLower(username)

	// Check if user exists
	var exists bool
	err := db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE username = ? AND deleted_at IS NULL)", username).Scan(&exists)
	if err != nil {
		return fmt.Errorf("error checking user existence: %v", err)
	}

	if exists {
		// Update existing user
		_, err = db.ExecContext(ctx, "UPDATE users SET strava_name = ? WHERE username = ? AND deleted_at IS NULL", stravaName, username)
	} else {
		nowSub3Days := time.Now().Add(3 * -24 * time.Hour).Unix()
		// Create new user with strava_name
		_, err = db.ExecContext(ctx, "INSERT INTO users (username, strava_name, status) VALUES (?, ?, ?)", username, stravaName, nowSub3Days)
	}

	if err != nil {
		return fmt.Errorf("error setting strava name: %v", err)
	}
	return nil
}

func setStravaID(ctx context.Context, username string, stravaID string) error {
	username = strings.ToLower(username)

	// Check if user exists
	var exists bool
	err := db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE username = ? AND deleted_at IS NULL)", username).Scan(&exists)
	if err != nil {
		return fmt.Errorf("error checking user existence: %v", err)
	}

	if exists {
		// Update existing user
		_, err = db.ExecContext(ctx, "UPDATE users SET strava_id_text = ? WHERE username = ? AND deleted_at IS NULL", stravaID, username)
	} else {
		nowSub3Days := time.Now().Add(3 * -24 * time.Hour).Unix()
		// Create new user with strava_name
		_, err = db.ExecContext(ctx, "INSERT INTO users (username, strava_id_text, status) VALUES (?, ?, ?)", username, stravaID, nowSub3Days)
	}

	if err != nil {
		return fmt.Errorf("error setting strava id: %v", err)
	}
	return nil
}

const timeFormat = "02 Jan 2006 15:04:05 MST"

func main() {
	initDB()
	defer db.Close()

	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Panic(err)
	}
	bot.Debug = verbose

	// Create context with cancellation for shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a cron instance and start it
	c := startDailyIncrementJob(ctx, bot)
	defer c.Stop() // Ensure cron jobs are stopped on shutdown

	// Create channel for shutdown signals
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)

	setRegex := regexp.MustCompile(`^/set @(\w+) (.+)$`)
	deleteRegex := regexp.MustCompile(`^/delete @(\w+)$`)
	restoreRegex := regexp.MustCompile(`^/restore @(\w+)$`)
	setoranRegex := regexp.MustCompile(`(?i).*(?:https://(?:strava\.app\.link/\w+|www\.strava\.com/activities/\d+)).*`)
	urlRegex := regexp.MustCompile(`https://(?:strava\.app\.link/\w+|www\.strava\.com/activities/\d+)`)
	nameRegex := regexp.MustCompile(`^/name @(\w+) (.+)$`)
	idRegex := regexp.MustCompile(`^/id @(\w+) (\d+)$`)
	setByLinkRegex := regexp.MustCompile(`^/sbl @(\w+) (.+)$`)

	// Create a channel to signal when message processing is done
	done := make(chan struct{})

	// Handle messages in a separate goroutine
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				log.Println("Shutting down message handler...")
				return
			case update, ok := <-updates:
				if !ok {
					return
				}
				if update.Message == nil {
					continue
				}

				if strings.Contains(update.Message.Text, "https://www.instagram.com/") {
					ddinstagramURL := ConvertToDDInstagramURL(update.Message.Text)
					if ddinstagramURL == "" {
						continue
					}

					msg := tgbotapi.NewMessage(chatID, ddinstagramURL)
					msg.MessageThreadId = update.Message.MessageThreadId
					bot.Send(msg)
					continue
				}

				if strings.Contains(update.Message.Text, "https://x.com/") {
					vxtwitterURL := ConvertToVXTwitterURL(update.Message.Text)
					if vxtwitterURL == "" {
						continue
					}

					msg := tgbotapi.NewMessage(chatID, vxtwitterURL)
					msg.MessageThreadId = update.Message.MessageThreadId
					bot.Send(msg)
					continue
				}

				if chatID != update.Message.Chat.ID {
					continue
				}
				userID := update.Message.From.ID
				text := update.Message.Text

				// Ensure user exists in database when they send a message
				username := update.Message.From.UserName
				if err := ensureUserExists(ctx, username); err != nil {
					log.Printf("Error ensuring user exists: %v", err)
				}

				if update.Message.ReplyToMessage == nil {
					continue
				}

				if update.Message.ReplyToMessage.ForumTopicCreated == nil {
					continue
				}

				// Handle group topic change
				if update.Message.ReplyToMessage.MessageThreadId != threadID {
					continue
				}

				if match := setByLinkRegex.FindStringSubmatch(text); match != nil {
					if !isAdmin(bot, chatID, userID) {
						msg := tgbotapi.NewMessage(chatID, "You must be an admin to use this command.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}

					username := match[1]

					// Extract the URL using the global regex
					activityURL := urlRegex.FindString(match[2])

					meta, err := validateActivity(ctx, activityURL, username)
					if err != nil {
						log.Println("Error validating activity: ", err)
						msg := tgbotapi.NewMessage(chatID, "Error validating activity. Error: "+err.Error())
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}

					if meta != nil {
						err := resetStatus(ctx, username, meta.Status, meta.DistanceMeter/1000)
						if err != nil {
							msg := tgbotapi.NewMessage(chatID, "Error resetting status.")
							msg.MessageThreadId = update.Message.MessageThreadId
							bot.Send(msg)
							continue
						}

						payload := `Selamat @%s! Status kamu sudah direset.

Tetap semangat berolahraga! 💪

Aktivitas: %s
Tanggal: %s
Jarak: %.02fkm
Pace: %s/km
Waktu: %s
Ketinggian: %.02fm
Foto Rute: %s`

						msg := tgbotapi.NewMessage(chatID,
							fmt.Sprintf(
								payload,
								username,
								meta.ActivityName,
								time.Unix(int64(meta.Status), 0).In(location).Format(timeFormat),
								meta.DistanceMeter/1000,
								meta.Pace,
								meta.Time,
								meta.Elevation,
								meta.ImageUrl,
							),
						)
						msg.MessageThreadId = update.Message.MessageThreadId
						_, err = bot.Send(msg)
						if err != nil {
							log.Println("Error sending message: ", err)
						}

					} else {
						msg := tgbotapi.NewMessage(chatID, "Activity tidak valid atau sudah lebih dari 2 hari yang lalu.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
					}

					continue
				}

				if match := restoreRegex.FindStringSubmatch(text); match != nil {
					if !isAdmin(bot, chatID, userID) {
						msg := tgbotapi.NewMessage(chatID, "You must be an admin to use this command.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}

					username := match[1]
					err := restoreUser(ctx, username)
					if err != nil {
						msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("Error: %v", err))
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}
					msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("✅ User @%s telah direstore dari database", username))
					msg.MessageThreadId = update.Message.MessageThreadId
					bot.Send(msg)
					continue
				}

				if match := setRegex.FindStringSubmatch(text); match != nil {
					if !isAdmin(bot, chatID, userID) {
						msg := tgbotapi.NewMessage(chatID, "You must be an admin to use this command.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}

					username := match[1]

					status, err := time.Parse(timeFormat, match[2])
					if err != nil {
						msg := tgbotapi.NewMessage(chatID, "Invalid status value. Please provide a valid number.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}

					err = setStatusUnix(ctx, username, int(status.Unix()))
					if err != nil {
						msg := tgbotapi.NewMessage(chatID, "Error setting status.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}
					msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("✅ Status @%s telah diset ke: %s", username, status.Format(timeFormat)))
					msg.MessageThreadId = update.Message.MessageThreadId
					bot.Send(msg)
					continue
				}

				if match := deleteRegex.FindStringSubmatch(text); match != nil {
					if !isAdmin(bot, chatID, userID) {
						msg := tgbotapi.NewMessage(chatID, "You must be an admin to use this command.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}

					username := match[1]
					err := deleteUser(ctx, username)
					if err != nil {
						msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("Error: %v", err))
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}
					msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("✅ User @%s telah dihapus dari database", username))
					msg.MessageThreadId = update.Message.MessageThreadId
					bot.Send(msg)
					continue
				}

				if text == "/stats" {
					stats, err := getTopStats(ctx)
					if err != nil {
						msg := tgbotapi.NewMessage(chatID, "Error retrieving statistics.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}

					var messageText string
					if len(stats) == 0 || (len(stats) == 1 && stats[0] == "No data available.") {
						messageText = "🎉 Selamat! Semua user sudah SetoRan (Setor Keringatan)!"
					} else {
						messageText = "📊 Statistik SetoRan (Setor Keringatan):\n\n" +
							"Berikut adalah daftar user yang belum SetoRan (Setor Keringatan) dalam waktu 3 hari atau lebih:\n" +
							strings.Join(stats, "\n") +
							"\n\nJangan lupa kirim link aktivitas Strava untuk mereset status ya! 💪"
					}

					msg := tgbotapi.NewMessage(chatID, messageText)
					msg.MessageThreadId = update.Message.MessageThreadId
					bot.Send(msg)
					continue
				}

				if text == "/distances" {
					msgText, err := getDistance(ctx)
					if err != nil {
						msg := tgbotapi.NewMessage(chatID, "Error retrieving distance.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}

					msg := tgbotapi.NewMessage(chatID, msgText)
					msg.MessageThreadId = update.Message.MessageThreadId
					bot.Send(msg)
					continue
				}

				if match := nameRegex.FindStringSubmatch(text); match != nil {
					if !isAdmin(bot, chatID, userID) {
						msg := tgbotapi.NewMessage(chatID, "You must be an admin to use this command.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}

					username := match[1]   // First capture group: the username
					stravaName := match[2] // Second capture group: the Strava name

					if err := setStravaName(ctx, username, stravaName); err != nil {
						msg := tgbotapi.NewMessage(chatID, "Error updating Strava name.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}

					msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("✅ Strava name untuk @%s telah diupdate menjadi: %s", username, stravaName))
					msg.MessageThreadId = update.Message.MessageThreadId
					bot.Send(msg)
					continue
				}

				if match := idRegex.FindStringSubmatch(text); match != nil {
					if !isAdmin(bot, chatID, userID) {
						msg := tgbotapi.NewMessage(chatID, "You must be an admin to use this command.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}

					username := match[1] // First capture group: the username
					stravaID := match[2] // Second capture group: the Strava name

					if err := setStravaID(ctx, username, stravaID); err != nil {
						log.Println("Error updating Strava id: ", err)
						msg := tgbotapi.NewMessage(chatID, "Error updating Strava id.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}

					msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("✅ Strava id untuk @%s telah diupdate menjadi: %s", username, stravaID))
					msg.MessageThreadId = update.Message.MessageThreadId
					bot.Send(msg)
					continue
				}
				if text == "/help" {
					helpText := `🤖 *Daftar Perintah*

*Untuk Semua Pengguna:*
• /stats - Tampilkan daftar pengguna yang belum SetoRan dalam waktu 3 hari atau lebih
• /help - Tampilkan pesan bantuan ini
• Post link Strava - Reset status dengan mengirim link aktivitas Strava (maksimal 2 hari yang lalu)

*Khusus Admin:*
• /set @username <02 Jan 2006 15:04:05 MST> - Atur status pengguna ke waktu tertentu
• /name @username <nama_strava> - Update nama Strava pengguna
• /delete @username - Hapus pengguna dari database
• /restore @username - Mengembalikan pengguna yang telah dihapus
• /sbl @username <link_strava> - Reset status pengguna lain menggunakan link Strava

Bot akan otomatis:
• Mengirim pengingat pada jam 8 pagi WIB untuk pengguna dengan status ≥ 3 hari

_Catatan: Gunakan perintah hanya di thread yang ditentukan._`

					msg := tgbotapi.NewMessage(chatID, helpText)
					msg.MessageThreadId = update.Message.MessageThreadId
					msg.ParseMode = "Markdown"
					bot.Send(msg)
					continue
				}

				if match := setoranRegex.FindString(text); match != "" {
					// Extract the URL using the global regex
					activityURL := urlRegex.FindString(match)

					meta, err := validateActivity(ctx, activityURL, username)
					if err != nil {
						log.Println("Error validating activity: ", err)
						msg := tgbotapi.NewMessage(chatID, "Error validating activity. Error: "+err.Error())
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}

					if meta != nil {
						username := update.Message.From.UserName
						err := resetStatus(ctx, username, meta.Status, meta.DistanceMeter/1000)
						if err != nil {
							msg := tgbotapi.NewMessage(chatID, "Error resetting status.")
							msg.MessageThreadId = update.Message.MessageThreadId
							bot.Send(msg)
							continue
						}

						payload := `Selamat @%s! Status kamu sudah direset.

Tetap semangat berolahraga! 💪

Aktivitas: %s
Tanggal: %s
Jarak: %.02fkm
Pace: %s/km
Waktu: %s
Ketinggian: %.02fm
Foto Rute: %s
`

						msg := tgbotapi.NewMessage(chatID,
							fmt.Sprintf(
								payload,
								username,
								meta.ActivityName,
								time.Unix(int64(meta.Status), 0).In(location).Format(timeFormat),
								meta.DistanceMeter/1000,
								meta.Pace,
								meta.Time,
								meta.Elevation,
								meta.ImageUrl,
							),
						)
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
					} else {
						msg := tgbotapi.NewMessage(chatID, "Activity tidak valid atau sudah lebih dari 2 hari yang lalu.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
					}
					continue
				}
			}
		}
	}()

	// Wait for shutdown signal
	<-shutdown
	log.Println("Shutdown signal received, starting graceful shutdown...")

	// Cancel context to stop message processing
	cancel()

	// Wait for message processing to complete with timeout
	shutdownTimeout := time.After(10 * time.Second)
	select {
	case <-done:
		log.Println("Message handler shut down successfully")
	case <-shutdownTimeout:
		log.Println("Shutdown timed out waiting for message handler")
	}

	log.Println("Application shutdown complete")
}

var re = regexp.MustCompile(`/activities/(\d+)`)

func ExtractStravaActivityURL(shareableURL string) (string, error) {
	// Look for the pattern /activities/NUMBER in the URL
	match := re.FindStringSubmatch(shareableURL)

	if len(match) < 2 {
		return "", fmt.Errorf("no activity ID found in URL")
	}

	// Construct the base Strava activity URL
	activityID := match[1]
	baseURL := "https://www.strava.com/activities/" + activityID

	return baseURL, nil
}

func validateActivity(ctx context.Context, activityURL string, username string) (meta *Activity, err error) {
	username = strings.ToLower(username)
	row := db.QueryRowContext(ctx, "SELECT strava_name, strava_id_text FROM users WHERE username = ? AND deleted_at IS NULL", username)
	var stravaName sql.NullString
	var stravaID sql.NullString
	err = row.Scan(&stravaName, &stravaID)
	if err != nil {
		return
	}

	return crawlling(activityURL, stravaName.String, stravaID.String)
}

func crawlling(activityURL, stravaName string, stravaID string) (meta *Activity, err error) {
	c2 := colly.NewCollector(
		colly.AllowedDomains("www.strava.com"),
	)

	// triggered when the scraper encounters an error
	c2.OnError(func(_ *colly.Response, err error) {
		fmt.Println("Something went wrong: ", err)
	})

	c2.OnHTML("#__NEXT_DATA__", func(e *colly.HTMLElement) {
		var data ResponseJson
		err = json.Unmarshal([]byte(e.Text), &data)
		if err != nil {
			fmt.Println(err)
			return
		}

		if stravaID == "" && stravaName != fmt.Sprintf("%s %s", data.Props.PageProps.Activity.Athlete.FirstName, data.Props.PageProps.Activity.Athlete.LastName) {
			err = fmt.Errorf("strava name not match")
			return
		}

		if stravaID != "" && stravaID != data.Props.PageProps.Activity.Athlete.ID {
			err = fmt.Errorf("strava id not match")
			return
		}

		paceMinute, paceSecond := GetPacePerKm(data.Props.PageProps.Activity.Scalars.MovingTime, data.Props.PageProps.Activity.Scalars.Distance/1000)

		hours, minutes, seconds := ExtractTime(data.Props.PageProps.Activity.Scalars.MovingTime)

		imgLocation := "-"

		if len(data.Props.PageProps.Activity.MapImages) > 0 &&
			len(data.Props.PageProps.Activity.Streams.Location) > 0 {
			imgLocation = data.Props.PageProps.Activity.MapImages[0].URL
		}

		timeZone := "+08:00"

		if len(data.Props.PageProps.Activity.Streams.Location) > 0 {
			timeZone = getUTCOffset(f.GetTimezoneName(data.Props.PageProps.Activity.Streams.Location[0].Lng, data.Props.PageProps.Activity.Streams.Location[0].Lat))
		}

		t, err := time.Parse(time.RFC3339, data.Props.PageProps.Activity.StartLocal+timeZone)
		if err != nil {
			fmt.Println(err)
			return
		}

		meta = &Activity{
			ActivityName:  data.Props.PageProps.Activity.Name,
			ActivityDate:  data.Props.PageProps.Activity.StartLocal,
			DistanceMeter: data.Props.PageProps.Activity.Scalars.Distance,
			Time:          fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds),
			Elevation:     data.Props.PageProps.Activity.Scalars.ElevationGain,
			Pace:          fmt.Sprintf("%02d:%02d", paceMinute, paceSecond),
			ImageUrl:      imgLocation,
			Status:        int(t.Unix()) + data.Props.PageProps.Activity.Scalars.MovingTime,
			TimeZone:      timeZone,
		}

		nowYear, nowWeek := time.Now().ISOWeek()
		tYear, tWeek := t.ISOWeek()
		if tYear != nowYear || tWeek != nowWeek {
			meta.DistanceMeter = 0
		}
	})

	if strings.Contains(activityURL, "www.strava.com") {
		c2.Visit(activityURL)
		return
	}

	// instantiate a new collector object
	c := colly.NewCollector(
		colly.AllowedDomains("strava.app.link"),
	)

	// triggered when a CSS selector matches an element
	c.OnHTML(".secondary-action", func(e *colly.HTMLElement) {
		activityURL, err := ExtractStravaActivityURL(e.Attr("href"))
		if err != nil {
			fmt.Println("Error extracting Strava activity URL: ", err)
		}

		c2.Visit(activityURL)
	})

	// open the target URL
	c.Visit(activityURL)

	return
}

func getUTCOffset(tzName string) string {
	loc, err := time.LoadLocation(tzName)
	if err != nil {
		return "Error: Invalid timezone"
	}

	now := time.Now().In(loc)
	_, offset := now.Zone()

	// Return "Z" if offset is 0 (UTC)
	if offset == 0 {
		return "Z"
	}

	// Format the offset as +HHMM or -HHMM
	sign := "+"
	if offset < 0 {
		sign = "-"
		offset = -offset
	}

	hours := offset / 3600
	minutes := (offset % 3600) / 60

	return fmt.Sprintf("%s%02d:%02d", sign, hours, minutes)
}

// ExtractTime takes a total number of seconds and returns the equivalent
// hours, minutes, and remaining seconds
func ExtractTime(totalSeconds int) (hours, minutes, seconds int) {
	// Calculate hours
	hours = totalSeconds / 3600

	// Calculate remaining seconds after extracting hours
	totalSeconds %= 3600

	// Calculate minutes
	minutes = totalSeconds / 60

	// Calculate remaining seconds after extracting minutes
	seconds = totalSeconds % 60

	return hours, minutes, seconds
}

func GetPacePerKm(seconds int, distanceKm float64) (minutes int, remainingSeconds int) {
	if distanceKm <= 0 {
		return 0, 0 // Avoid division by zero or negative values
	}

	// Calculate total seconds per kilometer
	secondsPerKm := float64(seconds) / distanceKm

	// Convert to minutes and seconds
	minutes = int(secondsPerKm) / 60
	remainingSeconds = int(math.Round(secondsPerKm)) % 60

	return minutes, remainingSeconds
}

func ConvertToDDInstagramURL(instagramURL string) (url string) {
	// Replace instagram with ddinstagram
	url = strings.Replace(instagramURL, "instagram.com", "ddinstagram.com", 1)

	// Remove everything before https://www.ddinstagram.com
	if idx := strings.Index(url, "https://www.ddinstagram.com"); idx != -1 {
		url = "Preview: " + url[idx:]
	}

	// Remove everything after ?
	if idx := strings.Index(url, "?"); idx != -1 {
		if url[idx-1] == '/' {
			url = url[:idx-1]

			ss := strings.Split(strings.Replace(url, "Preview: https://", "", 1), "/")
			if len(ss) == 2 {
				return ""
			}
			return
		}

		url = url[:idx]

		ss := strings.Split(strings.Replace(url, "Preview: https://", "", 1), "/")
		if len(ss) == 2 {
			return ""
		}
		return
	}

	return
}

func ConvertToVXTwitterURL(twitterURL string) (url string) {
	// Replace x.com with vxtwitter.com
	url = strings.Replace(twitterURL, "x.com", "vxtwitter.com", 1)

	// Remove everything before https://www.vxtwitter.com
	if idx := strings.Index(url, "https://www.vxtwitter.com"); idx != -1 {
		url = "Preview: " + url[idx:]
	}

	// Remove everything after ?
	if idx := strings.Index(url, "?"); idx != -1 {
		if url[idx-1] == '/' {
			url = url[:idx-1]

			ss := strings.Split(strings.Replace(url, "Preview: https://", "", 1), "/")
			if len(ss) == 2 {
				return ""
			}
			return
		}

		url = url[:idx]

		ss := strings.Split(strings.Replace(url, "Preview: https://", "", 1), "/")
		if len(ss) == 2 {
			return ""
		}
		return
	}

	return
}

func getDistance(ctx context.Context) (msg string, err error) {
	rows, err := db.QueryContext(ctx, "SELECT username, distance FROM users WHERE deleted_at IS NULL and distance > 0 ORDER BY distance DESC")
	if err != nil {
		return
	}
	defer rows.Close()

	var first float64
	var count int

	msg = "Distance:\n"

	for rows.Next() {
		var username string
		var distance float64
		err = rows.Scan(&username, &distance)
		if err != nil {
			return
		}
		if first == 0 {
			first = distance
		}
		// add message like bar based on percentage from first person
		percentage := distance / first
		multiple := int(percentage * 10)
		if multiple < 0 {
			multiple = 0
		}
		bar := fmt.Sprintf("|%s|", strings.Repeat("=", multiple))
		msg += fmt.Sprintf("%s @%s: %.02fkm", bar, username, distance)
		count++

		if count == 1 {
			msg += " (🏆)"
		}

		if count == 2 {
			msg += " (🥈)"
		}

		if count == 3 {
			msg += " (🥉)"
		}

		if count > 3 {
			msg += " (🏃)"
		}

		msg += "\n"
	}
	return
}
