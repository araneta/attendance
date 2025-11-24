package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
	"github.com/gorilla/websocket"
	"github.com/kataras/iris/v12"
	_ "gorm.io/driver/postgres"
	_ "gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Database Models
type User struct {
	ID           string    `gorm:"primaryKey" json:"id"`
	Username     string    `gorm:"not null" json:"username"`
	Email        string    `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash string    `gorm:"not null" json:"-"` // Hidden from JSON
	Role         string    `gorm:"default:'employee'" json:"role"`
	Metadata     string    `gorm:"type:text" json:"metadata,omitempty"`
	Active       bool      `gorm:"default:true" json:"active"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type Session struct {
	Token     string    `gorm:"primaryKey" json:"token"`
	UserID    string    `gorm:"not null;index" json:"userId"`
	ExpiresAt time.Time `gorm:"index" json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
}

type AttendanceRecord struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	UserID    string    `gorm:"index;not null" json:"userId"`
	Username  string    `json:"username"`
	QRCode    string    `gorm:"index" json:"qrCode"`
	Status    string    `gorm:"default:'present'" json:"status"`
	Timestamp time.Time `gorm:"index" json:"timestamp"`
	CreatedAt time.Time `json:"createdAt"`
}

// Add unique constraint: one user can only scan each QR code once
func (AttendanceRecord) TableName() string {
	return "attendance_records"
}

// This will be called after auto-migration
func addAttendanceConstraints(db *gorm.DB) {
	// Create unique index to prevent duplicate scans
	db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_user_qr_unique 
		ON attendance_records(user_id, qr_code)`)
}

type QRCode struct {
	Code      string    `gorm:"primaryKey" json:"code"`
	AdminID   string    `gorm:"not null" json:"adminId"`
	ExpiresAt time.Time `gorm:"index" json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
}

type WebhookConfig struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	URL       string    `gorm:"not null" json:"url"`
	Events    string    `gorm:"type:text" json:"events"` // JSON array
	Secret    string    `json:"secret"`
	Enabled   bool      `gorm:"default:true" json:"enabled"`
	CreatedAt time.Time `json:"createdAt"`
}

type APIKey struct {
	Key       string    `gorm:"primaryKey" json:"key"`
	Name      string    `gorm:"not null" json:"name"`
	Enabled   bool      `gorm:"default:true" json:"enabled"`
	CreatedAt time.Time `json:"createdAt"`
}

type ExternalAuthConfig struct {
	ID        int       `gorm:"primaryKey" json:"id"`
	Type      string    `json:"type"` // "api", "jwt", "oauth", "ldap", "none"
	Endpoint  string    `json:"endpoint,omitempty"`
	APIKey    string    `json:"apiKey,omitempty"`
	Enabled   bool      `gorm:"default:false" json:"enabled"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// WebSocket Types
type Client struct {
	ID     string
	UserID string
	Role   string
	Conn   *websocket.Conn
	Send   chan []byte
	Hub    *Hub
}

type Hub struct {
	clients    map[string]*Client
	register   chan *Client
	unregister chan *Client
	broadcast  chan Message
}

type Message struct {
	Type     string      `json:"type"`
	Payload  interface{} `json:"payload"`
	TargetID string      `json:"targetId,omitempty"`
}

type ScanRequest struct {
	QRCode string `json:"qrCode"`
	UserID string `json:"userId"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token"`
	User    User   `json:"user"`
	Message string `json:"message"`
}

var (
	db  *gorm.DB
	hub *Hub
)

// Initialize Database
func initDB() {
	var err error
	
	// Choose your database (uncomment one):
	
	// SQLite (easiest for development - no setup needed)
	db, err = gorm.Open(sqlite.Open("attendance.db"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	
	// PostgreSQL
	// dsn := "host=localhost user=postgres password=yourpassword dbname=attendance port=5432 sslmode=disable"
	// db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	
	// MySQL
	// dsn := "user:password@tcp(127.0.0.1:3306)/attendance?charset=utf8mb4&parseTime=True&loc=Local"
	// db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	
	log.Println("Database connected successfully")
	
	// Check if users table exists with old schema
	//var tableCount int64
	err = db.Exec("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='users'").Error
	hasOldUsers := err == nil
	
	if hasOldUsers {
		// Check if password_hash column exists
		var columnExists int
		db.Raw("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='password_hash'").Scan(&columnExists)
		
		if columnExists == 0 {
			log.Println("⚠️  Old database detected without authentication!")
			log.Println("⚠️  Backing up and recreating database with authentication...")
			
			// Backup old data
			type OldUser struct {
				ID        string
				Username  string
				Email     string
				Role      string
				Metadata  string
				Active    bool
				CreatedAt time.Time
				UpdatedAt time.Time
			}
			var oldUsers []OldUser
			db.Table("users").Find(&oldUsers)
			
			// Drop old table
			db.Migrator().DropTable(&User{})
			
			// Create new table with password_hash
			db.AutoMigrate(&User{})
			
			// Restore users with default password
			defaultPass, _ := bcrypt.GenerateFromPassword([]byte("changeme123"), bcrypt.DefaultCost)
			for _, oldUser := range oldUsers {
				newUser := User{
					ID:           oldUser.ID,
					Username:     oldUser.Username,
					Email:        oldUser.Email,
					PasswordHash: string(defaultPass),
					Role:         oldUser.Role,
					Metadata:     oldUser.Metadata,
					Active:       oldUser.Active,
					CreatedAt:    oldUser.CreatedAt,
					UpdatedAt:    oldUser.UpdatedAt,
				}
				db.Create(&newUser)
			}
			
			if len(oldUsers) > 0 {
				log.Printf("✅ Migrated %d existing users", len(oldUsers))
				log.Println("⚠️  All existing users now have password: changeme123")
				log.Println("⚠️  Users should change their passwords after first login!")
			}
		}
	}
	
	// Auto Migrate (create tables)
	err = db.AutoMigrate(
		&User{},
		&Session{},
		&AttendanceRecord{},
		&QRCode{},
		&WebhookConfig{},
		&APIKey{},
		&ExternalAuthConfig{},
	)
	
	if err != nil {
		log.Fatal("Failed to migrate database:", err)
	}
	
	// Add unique constraints
	addAttendanceConstraints(db)
	
	log.Println("Database tables migrated successfully")
	
	// Create default API key if not exists
	var count int64
	db.Model(&APIKey{}).Count(&count)
	if count == 0 {
		defaultKey := APIKey{
			Key:       "ak_test_key_12345",
			Name:      "Default Test Key",
			Enabled:   true,
			CreatedAt: time.Now(),
		}
		db.Create(&defaultKey)
		log.Println("Default API key created: ak_test_key_12345")
	}
	
	// Create default users if not exists
	db.Model(&User{}).Count(&count)
	if count == 0 {
		// Hash passwords
		adminPass, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
		userPass, _ := bcrypt.GenerateFromPassword([]byte("user123"), bcrypt.DefaultCost)

		defaultUsers := []User{
			{
				ID:           "user1",
				Username:     "John Doe",
				Email:        "john@example.com",
				PasswordHash: string(userPass),
				Role:         "employee",
				Active:       true,
			},
			{
				ID:           "user2",
				Username:     "Jane Smith",
				Email:        "jane@example.com",
				PasswordHash: string(userPass),
				Role:         "employee",
				Active:       true,
			},
			{
				ID:           "admin1",
				Username:     "Admin User",
				Email:        "admin@example.com",
				PasswordHash: string(adminPass),
				Role:         "admin",
				Active:       true,
			},
		}
		db.Create(&defaultUsers)
		log.Println("Default users created:")
		log.Println("  Admin: admin@example.com / admin123")
		log.Println("  User: john@example.com / user123")
		log.Println("  User: jane@example.com / user123")
	}
}

// Hub Management
func newHub() *Hub {
	return &Hub{
		clients:    make(map[string]*Client),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		broadcast:  make(chan Message),
	}
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client.ID] = client
			log.Printf("Client registered: %s (Role: %s, UserID: %s)", client.ID, client.Role, client.UserID)

		case client := <-h.unregister:
			if _, ok := h.clients[client.ID]; ok {
				delete(h.clients, client.ID)
				close(client.Send)
				log.Printf("Client unregistered: %s", client.ID)
			}

		case message := <-h.broadcast:
			for _, client := range h.clients {
				if message.TargetID == "" || client.UserID == message.TargetID {
					select {
					case client.Send <- mustMarshal(message):
					default:
						close(client.Send)
						delete(h.clients, client.ID)
					}
				}
			}
		}
	}
}

func (c *Client) readPump() {
	defer func() {
		c.Hub.unregister <- c
		c.Conn.Close()
	}()

	c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, _, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.Conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// Middleware
func apiKeyAuth(ctx iris.Context) {
	apiKey := ctx.GetHeader("X-API-Key")
	if apiKey == "" {
		ctx.StatusCode(iris.StatusUnauthorized)
		ctx.JSON(iris.Map{"error": "API key required"})
		ctx.StopExecution()
		return
	}

	var key APIKey
	if err := db.Where("key = ? AND enabled = ?", apiKey, true).First(&key).Error; err != nil {
		ctx.StatusCode(iris.StatusUnauthorized)
		ctx.JSON(iris.Map{"error": "Invalid or disabled API key"})
		ctx.StopExecution()
		return
	}

	ctx.Values().Set("apiKey", key)
	ctx.Next()
}

func sessionAuth(ctx iris.Context) {
	token := ctx.GetHeader("Authorization")
	if token == "" {
		token = ctx.URLParam("token") // Allow token in query param for WebSocket
	}

	if token == "" {
		ctx.StatusCode(iris.StatusUnauthorized)
		ctx.JSON(iris.Map{"error": "Authentication required"})
		ctx.StopExecution()
		return
	}

	var session Session
	if err := db.Where("token = ? AND expires_at > ?", token, time.Now()).First(&session).Error; err != nil {
		ctx.StatusCode(iris.StatusUnauthorized)
		ctx.JSON(iris.Map{"error": "Invalid or expired session"})
		ctx.StopExecution()
		return
	}

	var user User
	if err := db.First(&user, "id = ?", session.UserID).Error; err != nil {
		ctx.StatusCode(iris.StatusUnauthorized)
		ctx.JSON(iris.Map{"error": "User not found"})
		ctx.StopExecution()
		return
	}

	ctx.Values().Set("user", user)
	ctx.Values().Set("session", session)
	ctx.Next()
}

func adminOnly(ctx iris.Context) {
	user, ok := ctx.Values().Get("user").(User)
	if !ok || user.Role != "admin" {
		ctx.StatusCode(iris.StatusForbidden)
		ctx.JSON(iris.Map{"error": "Admin access required"})
		ctx.StopExecution()
		return
	}
	ctx.Next()
}

// Webhook trigger
func triggerWebhook(event string, data interface{}) {
	var webhooks []WebhookConfig
	db.Where("enabled = ?", true).Find(&webhooks)

	for _, webhook := range webhooks {
		var events []string
		json.Unmarshal([]byte(webhook.Events), &events)

		listenToEvent := false
		for _, e := range events {
			if e == event || e == "*" {
				listenToEvent = true
				break
			}
		}

		if listenToEvent {
			go sendWebhook(webhook, event, data)
		}
	}
}

func sendWebhook(webhook WebhookConfig, event string, data interface{}) {
	log.Printf("Triggering webhook: %s for event: %s", webhook.URL, event)
}

// API Handlers

// Authentication
func login(ctx iris.Context) {
	var req LoginRequest
	if err := ctx.ReadJSON(&req); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{"error": "Invalid request"})
		return
	}

	var user User
	if err := db.Where("email = ? AND active = ?", req.Email, true).First(&user).Error; err != nil {
		ctx.StatusCode(iris.StatusUnauthorized)
		ctx.JSON(iris.Map{
			"success": false,
			"message": "Invalid email or password",
		})
		return
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		ctx.StatusCode(iris.StatusUnauthorized)
		ctx.JSON(iris.Map{
			"success": false,
			"message": "Invalid email or password",
		})
		return
	}

	// Create session (valid for 24 hours)
	session := Session{
		Token:     generateID(),
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	if err := db.Create(&session).Error; err != nil {
		ctx.StatusCode(iris.StatusInternalServerError)
		ctx.JSON(iris.Map{"error": "Failed to create session"})
		return
	}

	ctx.JSON(LoginResponse{
		Success: true,
		Token:   session.Token,
		User:    user,
		Message: "Login successful",
	})
}

func logout(ctx iris.Context) {
	session, ok := ctx.Values().Get("session").(Session)
	if !ok {
		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{"error": "No active session"})
		return
	}

	db.Delete(&session)

	ctx.JSON(iris.Map{
		"success": true,
		"message": "Logged out successfully",
	})
}

func register(ctx iris.Context) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}

	if err := ctx.ReadJSON(&req); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{"error": "Invalid request"})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.StatusCode(iris.StatusInternalServerError)
		ctx.JSON(iris.Map{"error": "Failed to hash password"})
		return
	}

	user := User{
		ID:           generateID(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		Role:         req.Role,
		Active:       true,
	}

	if user.Role == "" {
		user.Role = "employee"
	}

	if err := db.Create(&user).Error; err != nil {
		ctx.StatusCode(iris.StatusConflict)
		ctx.JSON(iris.Map{"error": "Email already exists"})
		return
	}

	// Auto-login: create session
	session := Session{
		Token:     generateID(),
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	db.Create(&session)

	ctx.JSON(iris.Map{
		"success": true,
		"token":   session.Token,
		"user":    user,
		"message": "Registration successful",
	})
}

func generateQRCode(ctx iris.Context) {
	// Get authenticated user
	user, ok := ctx.Values().Get("user").(User)
	if !ok {
		ctx.StatusCode(iris.StatusUnauthorized)
		ctx.JSON(iris.Map{"error": "Authentication required"})
		return
	}

	// Only admins can generate QR codes
	if user.Role != "admin" {
		ctx.StatusCode(iris.StatusForbidden)
		ctx.JSON(iris.Map{"error": "Only admins can generate QR codes"})
		return
	}

	code := generateID()
	qrCode := QRCode{
		Code:      code,
		AdminID:   user.ID,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := db.Create(&qrCode).Error; err != nil {
		ctx.StatusCode(iris.StatusInternalServerError)
		ctx.JSON(iris.Map{"error": "Failed to create QR code"})
		return
	}

	// Auto-delete expired QR codes after 5 minutes
	go func() {
		time.Sleep(5 * time.Minute)
		db.Delete(&QRCode{}, "code = ?", code)
	}()

	triggerWebhook("qr_generated", iris.Map{
		"qrCode":  code,
		"adminId": user.ID,
	})

	ctx.JSON(iris.Map{
		"qrCode": code,
		"admin":  user.Username,
		"expiresAt": qrCode.ExpiresAt,
	})
}

func scanQRCode(ctx iris.Context) {
	var req ScanRequest

	if err := ctx.ReadJSON(&req); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{"error": err.Error()})
		return
	}

	var qrCode QRCode
	if err := db.Where("code = ?", req.QRCode).First(&qrCode).Error; err != nil {
		ctx.JSON(iris.Map{
			"success": false,
			"message": "Invalid or expired QR code",
		})
		return
	}

	if time.Now().After(qrCode.ExpiresAt) {
		ctx.JSON(iris.Map{
			"success": false,
			"message": "QR code has expired",
		})
		return
	}

	var user User
	if err := db.Where("id = ? AND active = ?", req.UserID, true).First(&user).Error; err != nil {
		ctx.JSON(iris.Map{
			"success": false,
			"message": "User not found or inactive",
		})
		return
	}

	// CRITICAL FIX: Check if user already scanned this QR code
	var existingRecord AttendanceRecord
	err := db.Where("user_id = ? AND qr_code = ?", user.ID, req.QRCode).First(&existingRecord).Error
	
	if err == nil {
		// User already scanned this QR code
		ctx.JSON(iris.Map{
			"success": false,
			"message": "You have already scanned this QR code",
			"existingRecord": existingRecord,
		})
		return
	}

	// OPTIONAL: Prevent duplicate attendance on the same day
	// Uncomment if you want only one attendance per user per day
	/*
	startOfDay := time.Now().Truncate(24 * time.Hour)
	endOfDay := startOfDay.Add(24 * time.Hour)
	
	var todayRecord AttendanceRecord
	err = db.Where("user_id = ? AND timestamp >= ? AND timestamp < ?", 
		user.ID, startOfDay, endOfDay).First(&todayRecord).Error
	
	if err == nil {
		ctx.JSON(iris.Map{
			"success": false,
			"message": "Attendance already recorded today",
			"existingRecord": todayRecord,
		})
		return
	}
	*/

	record := AttendanceRecord{
		ID:        generateID(),
		UserID:    user.ID,
		Username:  user.Username,
		QRCode:    req.QRCode,
		Status:    "present",
		Timestamp: time.Now(),
	}

	if err := db.Create(&record).Error; err != nil {
		ctx.StatusCode(iris.StatusInternalServerError)
		ctx.JSON(iris.Map{"error": "Failed to record attendance"})
		return
	}

	hub.broadcast <- Message{
		Type:     "attendance_scanned",
		Payload:  record,
		TargetID: qrCode.AdminID,
	}

	triggerWebhook("attendance_recorded", record)

	ctx.JSON(iris.Map{
		"success": true,
		"message": "Attendance recorded successfully",
		"record":  record,
	})
}

// User Management
func createUser(ctx iris.Context) {
	var user User
	if err := ctx.ReadJSON(&user); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{"error": err.Error()})
		return
	}

	if user.ID == "" {
		user.ID = generateID()
	}

	user.Active = true

	if err := db.Create(&user).Error; err != nil {
		ctx.StatusCode(iris.StatusConflict)
		ctx.JSON(iris.Map{"error": "User already exists or duplicate email"})
		return
	}

	ctx.JSON(iris.Map{
		"success": true,
		"user":    user,
		"message": "User created successfully",
	})
}

func getUser(ctx iris.Context) {
	userID := ctx.Params().Get("id")

	var user User
	if err := db.First(&user, "id = ?", userID).Error; err != nil {
		ctx.StatusCode(iris.StatusNotFound)
		ctx.JSON(iris.Map{"error": "User not found"})
		return
	}

	ctx.JSON(user)
}

func listUsers(ctx iris.Context) {
	var users []User
	db.Find(&users)

	ctx.JSON(iris.Map{
		"success": true,
		"count":   len(users),
		"users":   users,
	})
}

func updateUser(ctx iris.Context) {
	userID := ctx.Params().Get("id")

	var user User
	if err := db.First(&user, "id = ?", userID).Error; err != nil {
		ctx.StatusCode(iris.StatusNotFound)
		ctx.JSON(iris.Map{"error": "User not found"})
		return
	}

	var updates User
	if err := ctx.ReadJSON(&updates); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{"error": err.Error()})
		return
	}

	db.Model(&user).Updates(updates)

	ctx.JSON(iris.Map{
		"success": true,
		"user":    user,
	})
}

func deleteUser(ctx iris.Context) {
	userID := ctx.Params().Get("id")

	if err := db.Delete(&User{}, "id = ?", userID).Error; err != nil {
		ctx.StatusCode(iris.StatusInternalServerError)
		ctx.JSON(iris.Map{"error": "Failed to delete user"})
		return
	}

	ctx.JSON(iris.Map{"success": true})
}

func syncUsers(ctx iris.Context) {
	var req struct {
		Users          []map[string]interface{} `json:"users"`
		UpdateExisting bool                     `json:"updateExisting"`
	}

	if err := ctx.ReadJSON(&req); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{"error": err.Error()})
		return
	}

	synced := 0
	updated := 0
	skipped := 0
	var errors []string

	for _, userData := range req.Users {
		userID, ok := userData["id"].(string)
		if !ok || userID == "" {
			errors = append(errors, "User without ID skipped")
			skipped++
			continue
		}

		var existingUser User
		exists := db.First(&existingUser, "id = ?", userID).Error == nil

		if exists && !req.UpdateExisting {
			skipped++
			continue
		}

		user := User{
			ID:       userID,
			Username: getStringValue(userData, "username"),
			Email:    getStringValue(userData, "email"),
			Role:     getStringValue(userData, "role"),
			Active:   true,
		}

		if metadata, ok := userData["metadata"]; ok {
			metadataJSON, _ := json.Marshal(metadata)
			user.Metadata = string(metadataJSON)
		}

		if exists {
			db.Model(&existingUser).Updates(user)
			updated++
		} else {
			if err := db.Create(&user).Error; err != nil {
				errors = append(errors, fmt.Sprintf("Failed to create user %s: %v", userID, err))
				skipped++
			} else {
				synced++
			}
		}
	}

	ctx.JSON(iris.Map{
		"success": true,
		"synced":  synced,
		"updated": updated,
		"skipped": skipped,
		"total":   len(req.Users),
		"errors":  errors,
		"message": fmt.Sprintf("Synced: %d, Updated: %d, Skipped: %d", synced, updated, skipped),
	})
}

// Attendance Records
func getAttendanceRecords(ctx iris.Context) {
	userID := ctx.URLParam("userId")
	startDate := ctx.URLParam("startDate")
	endDate := ctx.URLParam("endDate")

	query := db.Model(&AttendanceRecord{})

	if userID != "" {
		query = query.Where("user_id = ?", userID)
	}
	if startDate != "" {
		query = query.Where("timestamp >= ?", startDate)
	}
	if endDate != "" {
		query = query.Where("timestamp <= ?", endDate)
	}

	var records []AttendanceRecord
	query.Order("timestamp DESC").Find(&records)

	ctx.JSON(iris.Map{
		"success": true,
		"count":   len(records),
		"records": records,
	})
}

func getAttendanceRecord(ctx iris.Context) {
	recordID := ctx.Params().Get("id")

	var record AttendanceRecord
	if err := db.First(&record, "id = ?", recordID).Error; err != nil {
		ctx.StatusCode(iris.StatusNotFound)
		ctx.JSON(iris.Map{"error": "Record not found"})
		return
	}

	ctx.JSON(record)
}

// Webhook Management
func createWebhook(ctx iris.Context) {
	var req struct {
		URL    string   `json:"url"`
		Events []string `json:"events"`
		Secret string   `json:"secret"`
	}

	if err := ctx.ReadJSON(&req); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{"error": err.Error()})
		return
	}

	eventsJSON, _ := json.Marshal(req.Events)

	webhook := WebhookConfig{
		ID:      generateID(),
		URL:     req.URL,
		Events:  string(eventsJSON),
		Secret:  req.Secret,
		Enabled: true,
	}

	db.Create(&webhook)

	ctx.JSON(iris.Map{
		"success":   true,
		"webhookId": webhook.ID,
		"webhook":   webhook,
	})
}

func listWebhooks(ctx iris.Context) {
	var webhooks []WebhookConfig
	db.Find(&webhooks)

	ctx.JSON(iris.Map{
		"success":  true,
		"webhooks": webhooks,
	})
}

func deleteWebhook(ctx iris.Context) {
	webhookID := ctx.Params().Get("id")
	db.Delete(&WebhookConfig{}, "id = ?", webhookID)
	ctx.JSON(iris.Map{"success": true})
}

// API Key Management
func createAPIKey(ctx iris.Context) {
	var req struct {
		Name string `json:"name"`
	}

	if err := ctx.ReadJSON(&req); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{"error": err.Error()})
		return
	}

	apiKey := APIKey{
		Key:     "ak_" + generateID(),
		Name:    req.Name,
		Enabled: true,
	}

	db.Create(&apiKey)

	ctx.JSON(iris.Map{
		"success": true,
		"apiKey":  apiKey,
	})
}

func listAPIKeys(ctx iris.Context) {
	var keys []APIKey
	db.Find(&keys)

	ctx.JSON(iris.Map{
		"success": true,
		"apiKeys": keys,
	})
}

func revokeAPIKey(ctx iris.Context) {
	key := ctx.Params().Get("key")
	db.Model(&APIKey{}).Where("key = ?", key).Update("enabled", false)
	ctx.JSON(iris.Map{"success": true})
}

// Helper Functions
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func mustMarshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func getStringValue(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func main() {
	// Initialize Database
	initDB()

	// Initialize Hub
	hub = newHub()
	go hub.run()

	app := iris.New()

	// WebSocket upgrader
	var wsUpgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	// CORS middleware
	app.UseRouter(func(ctx iris.Context) {
		ctx.Header("Access-Control-Allow-Origin", "*")
		ctx.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		ctx.Header("Access-Control-Allow-Headers", "*")

		if ctx.Method() == iris.MethodOptions {
			ctx.StatusCode(iris.StatusNoContent)
			return
		}

		ctx.Next()
	})

	// WebSocket endpoint
	app.Get("/ws", func(ctx iris.Context) {
		role := ctx.URLParam("role")
		userID := ctx.URLParam("userId")

		if role == "" || userID == "" {
			ctx.StatusCode(iris.StatusBadRequest)
			ctx.JSON(iris.Map{"error": "role and userId parameters required"})
			return
		}

		conn, err := wsUpgrader.Upgrade(ctx.ResponseWriter(), ctx.Request(), nil)
		if err != nil {
			log.Printf("WebSocket upgrade error: %v", err)
			return
		}

		client := &Client{
			ID:     generateID(),
			UserID: userID,
			Role:   role,
			Conn:   conn,
			Send:   make(chan []byte, 256),
			Hub:    hub,
		}

		hub.register <- client
		go client.writePump()
		go client.readPump()
	})

	// Public API routes (authentication)
	api := app.Party("/api")
	{
		api.Post("/login", login)
		api.Post("/register", register)
		api.Post("/logout", sessionAuth, logout)

		// QR code endpoints (require authentication)
		qr := api.Party("/qr", sessionAuth)
		{
			qr.Post("/generate", adminOnly, generateQRCode)
			qr.Post("/scan", scanQRCode)
		}
	}

	// Integration API routes (requires API key)
	integrationAPI := app.Party("/api/v1", apiKeyAuth)
	{
		integrationAPI.Get("/attendance", getAttendanceRecords)
		integrationAPI.Get("/attendance/{id}", getAttendanceRecord)

		integrationAPI.Post("/users", createUser)
		integrationAPI.Get("/users", listUsers)
		integrationAPI.Get("/users/{id}", getUser)
		integrationAPI.Put("/users/{id}", updateUser)
		integrationAPI.Delete("/users/{id}", deleteUser)
		integrationAPI.Post("/users/sync", syncUsers)

		integrationAPI.Post("/webhooks", createWebhook)
		integrationAPI.Get("/webhooks", listWebhooks)
		integrationAPI.Delete("/webhooks/{id}", deleteWebhook)

		integrationAPI.Post("/api-keys", createAPIKey)
		integrationAPI.Get("/api-keys", listAPIKeys)
		integrationAPI.Delete("/api-keys/{key}", revokeAPIKey)
	}

	log.Println("✅ Server starting on :8080")
	log.Println("✅ Database: SQLite (attendance.db)")
	log.Println("✅ Default API Key: ak_test_key_12345")
	app.Listen(":8080")
}
