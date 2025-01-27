package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	tgbotapi "github.com/egovorukhin/telebot-api"
	"github.com/gocolly/colly"
	_ "github.com/mattn/go-sqlite3"
	"github.com/robfig/cron/v3"
)

var (
	db       *sql.DB
	botToken string
	chatID   int64
	threadID int
	verbose  bool
)

func init() {
	// Define flags for token and chat ID
	flag.StringVar(&botToken, "token", "", "Telegram bot token")
	flag.Int64Var(&chatID, "id", 0, "Telegram chat ID")
	flag.IntVar(&threadID, "thread", 0, "Telegram thread ID")
	flag.BoolVar(&verbose, "v", false, "Enable verbose logging")
	flag.Parse()

	if botToken == "" || chatID == 0 || threadID == 0 {
		log.Fatal("Bot token, chat ID, and thread ID must be provided as flags.")
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
}

// Increments the specified user's status
func incrementStatus(ctx context.Context, username string) (int, error) {
	username = strings.ToLower(username)

	var status int
	err := db.QueryRowContext(ctx, "SELECT status FROM users WHERE username = ?", username).Scan(&status)
	if err == sql.ErrNoRows {
		_, err := db.ExecContext(ctx, "INSERT INTO users (username, status) VALUES (?, 1)", username)
		if err != nil {
			return 0, err
		}
		return 1, nil
	} else if err != nil {
		return 0, err
	}

	status++
	_, err = db.ExecContext(ctx, "UPDATE users SET status = ? WHERE username = ?", status, username)
	if err != nil {
		return 0, err
	}
	return status, nil
}

// Resets the specified user's status to 0, adding them if they don't exist
func resetStatus(ctx context.Context, username string) error {
	username = strings.ToLower(username)

	var exists bool
	err := db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", username).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		_, err = db.ExecContext(ctx, "UPDATE users SET status = 0 WHERE username = ?", username)
	} else {
		_, err = db.ExecContext(ctx, "INSERT INTO users (username, status) VALUES (?, 0)", username)
	}

	return err
}

// Increments all users' status every day at 12 AM Jakarta time
func incrementAllUsers(ctx context.Context) {
	_, err := db.ExecContext(ctx, "UPDATE users SET status = status + 1")
	if err != nil {
		log.Println("Error incrementing all users' status:", err)
	} else {
		log.Println("All users' status incremented successfully at 12 AM Jakarta time.")
	}
}

// Add new function to check and notify users with high status
func notifyHighStatusUsers(ctx context.Context, bot *tgbotapi.BotAPI) {
	rows, err := db.QueryContext(ctx, "SELECT username, status FROM users WHERE status >= 3")
	if err != nil {
		log.Println("Error querying users:", err)
		return
	}
	defer rows.Close()

	var pemalas []string
	for rows.Next() {
		var username string
		var status int
		if err := rows.Scan(&username, &status); err != nil {
			log.Println("Error scanning username:", err)
			continue
		}
		pemalas = append(pemalas, fmt.Sprintf("@%s: %d hari", username, status))
	}

	if err = rows.Err(); err != nil {
		log.Println("Error iterating rows:", err)
		return
	}

	if len(pemalas) > 0 {
		message := "🚨 Reminder untuk olahraga!\n\nUser yang belum olahraga 3 hari atau lebih:\n" +
			strings.Join(pemalas, "\n") +
			"\n\nJangan lupa post aktivitas dengan hashtag #beatyesterday atau #garmin ya!"
		msg := tgbotapi.NewMessage(chatID, message)
		msg.MessageThreadId = threadID
		_, err := bot.Send(msg)
		if err != nil {
			log.Println("Error sending notification:", err)
		}
	} else {
		message := "🎉 Selamat! Semua user rajin berolahraga! Pertahankan ya! 💪"
		msg := tgbotapi.NewMessage(chatID, message)
		msg.MessageThreadId = threadID
		_, err := bot.Send(msg)
		if err != nil {
			log.Println("Error sending notification:", err)
		}
	}
}

// Update startDailyIncrementJob to include both cron jobs
func startDailyIncrementJob(ctx context.Context, bot *tgbotapi.BotAPI) *cron.Cron {
	location, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		log.Fatal("Failed to load Jakarta timezone:", err)
	}

	c := cron.New(cron.WithLocation(location))

	// Midnight job to increment all users
	_, err = c.AddFunc("0 0 * * *", func() {
		incrementAllUsers(ctx)
	})
	if err != nil {
		log.Fatal("Failed to schedule increment cron job:", err)
	}

	// 8 AM job to notify about high status users
	_, err = c.AddFunc("0 8 * * *", func() {
		notifyHighStatusUsers(ctx, bot)
	})
	if err != nil {
		log.Fatal("Failed to schedule notification cron job:", err)
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
	rows, err := db.QueryContext(ctx, "SELECT username, status FROM users where status > 0 ORDER BY status DESC LIMIT 10")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []string
	for rows.Next() {
		var username string
		var status int
		err := rows.Scan(&username, &status)
		if err != nil {
			return nil, err
		}
		stats = append(stats, fmt.Sprintf("@%s: %d hari", username, status))
	}

	if len(stats) == 0 {
		return []string{"No data available."}, nil
	}

	return stats, nil
}

// Sets the specified user's status to the given value
func setStatus(ctx context.Context, username string, status int) error {
	username = strings.ToLower(username)

	var exists bool
	err := db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", username).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		_, err = db.ExecContext(ctx, "UPDATE users SET status = ? WHERE username = ?", status, username)
	} else {
		_, err = db.ExecContext(ctx, "INSERT INTO users (username, status) VALUES (?, ?)", username, status)
	}

	return err
}

// Deletes the specified user from the database
func deleteUser(ctx context.Context, username string) error {
	username = strings.ToLower(username)
	result, err := db.ExecContext(ctx, "DELETE FROM users WHERE username = ?", username)
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
	err := db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", username).Scan(&exists)
	if err != nil {
		return err
	}

	if !exists {
		_, err = db.ExecContext(ctx, "INSERT INTO users (username, status) VALUES (?, 0)", username)
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
	err := db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", username).Scan(&exists)
	if err != nil {
		return fmt.Errorf("error checking user existence: %v", err)
	}

	if exists {
		// Update existing user
		_, err = db.ExecContext(ctx, "UPDATE users SET strava_name = ? WHERE username = ?", stravaName, username)
	} else {
		// Create new user with strava_name
		_, err = db.ExecContext(ctx, "INSERT INTO users (username, strava_name, status) VALUES (?, ?, 0)", username, stravaName)
	}

	if err != nil {
		return fmt.Errorf("error setting strava name: %v", err)
	}
	return nil
}

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

	addRegex := regexp.MustCompile(`^/add @(\w+)$`)
	resetRegex := regexp.MustCompile(`^/reset @(\w+)$`)
	setRegex := regexp.MustCompile(`^/set @(\w+) (\d+)$`)
	deleteRegex := regexp.MustCompile(`^/delete @(\w+)$`)
	hashtagRegex := regexp.MustCompile(`#(beatyesterday|garmin)`)
	setoranRegex := regexp.MustCompile(`(?i).*(?:https://(?:strava\.app\.link/\w+|www\.strava\.com/activities/\d+)).*`)
	urlRegex := regexp.MustCompile(`https://(?:strava\.app\.link/\w+|www\.strava\.com/activities/\d+)`)
	nameRegex := regexp.MustCompile(`^/name @(\w+) (.+)$`)

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

				// Check for hashtags first
				if hashtagRegex.MatchString(text) {
					continue
					// username := update.Message.From.UserName
					// if username != "" {
					// 	err := resetStatus(ctx, username)
					// 	if err != nil {
					// 		msg := tgbotapi.NewMessage(chatID, "Error resetting status.")
					// 		msg.MessageThreadId = update.Message.MessageThreadId
					// 		bot.Send(msg)
					// 		continue
					// 	}
					// 	msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("🎉 Selamat @%s! Status kamu sudah direset ke 0.\n\nTetap semangat berolahraga! 💪", username))
					// 	msg.MessageThreadId = update.Message.MessageThreadId
					// 	bot.Send(msg)
					// 	continue
					// }
				}

				if match := addRegex.FindStringSubmatch(text); match != nil {
					continue
					// if !isAdmin(bot, chatID, userID) {
					// 	msg := tgbotapi.NewMessage(chatID, "You must be an admin to use this command.")
					// 	msg.MessageThreadId = update.Message.MessageThreadId
					// 	bot.Send(msg)
					// 	continue
					// }

					// username := match[1]
					// status, err := incrementStatus(ctx, username)
					// if err != nil {
					// 	msg := tgbotapi.NewMessage(chatID, "Error updating status.")
					// 	msg.MessageThreadId = update.Message.MessageThreadId
					// 	bot.Send(msg)
					// 	continue
					// }
					// msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("⚠️ Status @%s bertambah menjadi: %d hari\n\nAyo segera post aktivitas dengan hashtag #beatyesterday atau #garmin! 🏃‍♂️", username, status))
					// msg.MessageThreadId = update.Message.MessageThreadId
					// bot.Send(msg)

				} else if match := resetRegex.FindStringSubmatch(text); match != nil {
					continue
					// if !isAdmin(bot, chatID, userID) {
					// 	msg := tgbotapi.NewMessage(chatID, "You must be an admin to use this command.")
					// 	msg.MessageThreadId = update.Message.MessageThreadId
					// 	bot.Send(msg)
					// 	continue
					// }

					// username := match[1]
					// err := resetStatus(ctx, username)
					// if err != nil {
					// 	msg := tgbotapi.NewMessage(chatID, "Error resetting status.")
					// 	msg.MessageThreadId = update.Message.MessageThreadId
					// 	bot.Send(msg)
					// 	continue
					// }
					// msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("🎉 Selamat @%s! Status kamu sudah direset ke 0.\n\nTetap semangat berolahraga! 💪", username))
					// msg.MessageThreadId = update.Message.MessageThreadId
					// bot.Send(msg)

				} else if match := setRegex.FindStringSubmatch(text); match != nil {
					if !isAdmin(bot, chatID, userID) {
						msg := tgbotapi.NewMessage(chatID, "You must be an admin to use this command.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}

					username := match[1]
					status, err := strconv.Atoi(match[2])
					if err != nil {
						msg := tgbotapi.NewMessage(chatID, "Invalid status value. Please provide a valid number.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}

					if status < 0 {
						msg := tgbotapi.NewMessage(chatID, "Status tidak boleh kurang dari 0.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}

					err = setStatus(ctx, username, status)
					if err != nil {
						msg := tgbotapi.NewMessage(chatID, "Error setting status.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}
					msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("✅ Status @%s telah diset ke: %d hari", username, status))
					msg.MessageThreadId = update.Message.MessageThreadId
					bot.Send(msg)

				} else if match := deleteRegex.FindStringSubmatch(text); match != nil {
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

				} else if text == "/stats" {
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
							"Berikut adalah daftar user yang belum SetoRan (Setor Keringatan) dalam satuan hari:\n" +
							strings.Join(stats, "\n") +
							"\n\nJangan lupa post aktivitas dengan hashtag #beatyesterday atau #garmin untuk reset status ya! 💪"
					}

					msg := tgbotapi.NewMessage(chatID, messageText)
					msg.MessageThreadId = update.Message.MessageThreadId
					bot.Send(msg)
				} else if match := nameRegex.FindStringSubmatch(text); match != nil {
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
				} else if text == "/help" {
					helpText := `🤖 *Daftar Perintah*

*Untuk Semua Pengguna:*
• /stats - Tampilkan 10 pengguna teratas yang belum olahraga
• Post link Strava - Reset status dengan mengirim link aktivitas Strava (maksimal 2 hari yang lalu)

*Khusus Admin:*
• /set @username <angka> - Atur status pengguna ke angka tertentu
• /name @username <nama_strava> - Update nama Strava pengguna
• /delete @username - Hapus pengguna dari database

Bot akan otomatis:
• Menambah status semua pengguna pada jam 12 malam WIB
• Mengirim pengingat pada jam 8 pagi WIB untuk pengguna dengan status ≥ 3 hari

_Catatan: Gunakan perintah hanya di thread yang ditentukan._`

					msg := tgbotapi.NewMessage(chatID, helpText)
					msg.MessageThreadId = update.Message.MessageThreadId
					msg.ParseMode = "Markdown"
					bot.Send(msg)
				} else if match := setoranRegex.FindString(text); match != "" {
					// Extract the URL using the global regex
					activityURL := urlRegex.FindString(match)

					valid, err := validateActivity(ctx, activityURL, username)
					if err != nil {
						msg := tgbotapi.NewMessage(chatID, "Error validating activity.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
						continue
					}

					if valid {
						username := update.Message.From.UserName
						err := resetStatus(ctx, username)
						if err != nil {
							msg := tgbotapi.NewMessage(chatID, "Error resetting status.")
							msg.MessageThreadId = update.Message.MessageThreadId
							bot.Send(msg)
							continue
						}
						msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("🎉 Selamat @%s! Status kamu sudah direset ke 0.\n\nTetap semangat berolahraga! 💪", username))
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
					} else {
						msg := tgbotapi.NewMessage(chatID, "Activity tidak valid atau sudah lebih dari 2 hari yang lalu.")
						msg.MessageThreadId = update.Message.MessageThreadId
						bot.Send(msg)
					}
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

var re2 = regexp.MustCompile(`(?:on|On) ([A-Z][a-z]+ \d{1,2}, \d{4})`)

func ExtractDateFromStravaTitle(title string) (time.Time, error) {
	// Regular expression to match the date pattern
	match := re2.FindStringSubmatch(title)

	if len(match) < 2 {
		return time.Time{}, fmt.Errorf("no date found in title")
	}

	// Parse the date string in local time first
	date, err := time.Parse("January 2, 2006", match[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse date: %v", err)
	}

	// Load Asia/Jakarta timezone
	jakartaLoc, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to load Jakarta timezone: %v", err)
	}

	// Convert the date to Asia/Jakarta timezone
	jakartaDate := date.In(jakartaLoc)

	return jakartaDate, nil
}

func validateActivity(ctx context.Context, activityURL string, username string) (bool, error) {
	row := db.QueryRowContext(ctx, "SELECT strava_name FROM users WHERE username = ?", username)
	var stravaName string
	err := row.Scan(&stravaName)
	if err != nil {
		return false, err
	}
	var valid bool
	c2 := colly.NewCollector(
		colly.AllowedDomains("www.strava.com"),
	)

	// triggered when the scraper encounters an error
	c2.OnError(func(_ *colly.Response, err error) {
		fmt.Println("Something went wrong: ", err)
	})

	// triggered when a CSS selector matches an element
	c2.OnHTML("meta", func(e *colly.HTMLElement) {
		// printing all URLs associated with the <a> tag on the page
		if e.Attr("name") == "description" {
			content := e.Attr("content")
			if !strings.Contains(content, stravaName) {
				valid = false
				return
			}

			date, err := ExtractDateFromStravaTitle(content)
			if err != nil {
				fmt.Println("Error extracting date from title: ", err)
			}

			if date.After(time.Now().AddDate(0, 0, -1)) {
				valid = true
			}
		}
	})

	if strings.Contains(activityURL, "www.strava.com") {
		c2.Visit(activityURL)
		return valid, nil
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
	return valid, nil
}
