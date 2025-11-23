package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kataras/iris/v12"
)

type Client struct {
	ID     string
	UserID string
	Role   string // "admin" or "user"
	Conn   *websocket.Conn
	Send   chan []byte
	Hub    *Hub
}

type Hub struct {
	clients    map[string]*Client
	register   chan *Client
	unregister chan *Client
	broadcast  chan Message
	mu         sync.RWMutex
}

type Message struct {
	Type     string      `json:"type"`
	Payload  interface{} `json:"payload"`
	TargetID string      `json:"targetId,omitempty"`
}

type QRCode struct {
	Code      string    `json:"code"`
	AdminID   string    `json:"adminId"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type ScanRequest struct {
	QRCode string `json:"qrCode"`
	UserID string `json:"userId"`
}

type AttendanceRecord struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId"`
	Username  string    `json:"username"`
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"`
	QRCode    string    `json:"qrCode"`
}

type WebhookConfig struct {
	URL     string   `json:"url"`
	Events  []string `json:"events"`
	Secret  string   `json:"secret"`
	Enabled bool     `json:"enabled"`
}

type APIKey struct {
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
	Enabled   bool      `json:"enabled"`
}

type User struct {
	ID        string                 `json:"id"`
	Username  string                 `json:"username"`
	Email     string                 `json:"email"`
	Role      string                 `json:"role"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Active    bool                   `json:"active"`
	CreatedAt time.Time              `json:"createdAt"`
}

type UserValidationRequest struct {
	UserID string `json:"userId"`
	Token  string `json:"token,omitempty"`
}

type UserValidationResponse struct {
	Valid   bool   `json:"valid"`
	User    *User  `json:"user,omitempty"`
	Message string `json:"message,omitempty"`
}

type ExternalAuthConfig struct {
	Type     string `json:"type"` // "api", "jwt", "oauth", "ldap", "none"
	Endpoint string `json:"endpoint,omitempty"`
	APIKey   string `json:"apiKey,omitempty"`
	Enabled  bool   `json:"enabled"`
}

var (
	hub                *Hub
	qrCodes            = make(map[string]QRCode)
	qrMutex            sync.RWMutex
	attendanceRecords  = make(map[string]AttendanceRecord)
	recordsMutex       sync.RWMutex
	webhooks           = make(map[string]WebhookConfig)
	webhooksMutex      sync.RWMutex
	apiKeys            = make(map[string]APIKey)
	apiKeysMutex       sync.RWMutex
	users              = make(map[string]User)
	usersMutex         sync.RWMutex
	externalAuthConfig = ExternalAuthConfig{Type: "none", Enabled: false}
	authConfigMutex    sync.RWMutex
	jwtSecret          = []byte("your-secret-key-change-this")
)

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
			h.mu.Lock()
			h.clients[client.ID] = client
			h.mu.Unlock()
			log.Printf("Client registered: %s (Role: %s, UserID: %s)", client.ID, client.Role, client.UserID)

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client.ID]; ok {
				delete(h.clients, client.ID)
				close(client.Send)
				log.Printf("Client unregistered: %s", client.ID)
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			h.mu.RLock()
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
			h.mu.RUnlock()
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

// API Key Authentication Middleware
func apiKeyAuth(ctx iris.Context) {
	apiKey := ctx.GetHeader("X-API-Key")
	if apiKey == "" {
		ctx.StatusCode(iris.StatusUnauthorized)
		ctx.JSON(iris.Map{"error": "API key required"})
		ctx.StopExecution()
		return
	}

	apiKeysMutex.RLock()
	key, exists := apiKeys[apiKey]
	apiKeysMutex.RUnlock()

	if !exists || !key.Enabled {
		ctx.StatusCode(iris.StatusUnauthorized)
		ctx.JSON(iris.Map{"error": "Invalid or disabled API key"})
		ctx.StopExecution()
		return
	}

	ctx.Values().Set("apiKey", key)
	ctx.Next()
}

// Webhook trigger function
func triggerWebhook(event string, data interface{}) {
	webhooksMutex.RLock()
	defer webhooksMutex.RUnlock()

	for _, webhook := range webhooks {
		if !webhook.Enabled {
			continue
		}

		// Check if webhook listens to this event
		listenToEvent := false
		for _, e := range webhook.Events {
			if e == event || e == "*" {
				listenToEvent = true
				break
			}
		}

		if !listenToEvent {
			continue
		}

		// Send webhook in goroutine (non-blocking)
		go sendWebhook(webhook, event, data)
	}
}

func sendWebhook(webhook WebhookConfig, event string, data interface{}) {
	// In production, use proper HTTP client with retry logic
	log.Printf("Triggering webhook: %s for event: %s", webhook.URL, event)
	// Implementation would use http.Post with the webhook.URL
}

// === API Handlers ===

func generateQRCode(ctx iris.Context) {
	var req struct {
		AdminID string `json:"adminId"`
	}

	if err := ctx.ReadJSON(&req); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{"error": err.Error()})
		return
	}

	code := generateID()
	qrCode := QRCode{
		Code:      code,
		AdminID:   req.AdminID,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	qrMutex.Lock()
	qrCodes[code] = qrCode
	qrMutex.Unlock()

	go func() {
		time.Sleep(5 * time.Minute)
		qrMutex.Lock()
		delete(qrCodes, code)
		qrMutex.Unlock()
	}()

	triggerWebhook("qr_generated", iris.Map{
		"qrCode":  code,
		"adminId": req.AdminID,
	})

	ctx.JSON(iris.Map{"qrCode": code})
}

func scanQRCode(ctx iris.Context) {
	var req ScanRequest

	if err := ctx.ReadJSON(&req); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{"error": err.Error()})
		return
	}

	qrMutex.RLock()
	qrCode, exists := qrCodes[req.QRCode]
	qrMutex.RUnlock()

	if !exists {
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

	// Validate user (internal or external)
	user, err := validateUser(req.UserID, "")
	if err != nil {
		ctx.JSON(iris.Map{
			"success": false,
			"message": "User validation failed: " + err.Error(),
		})
		return
	}

	record := AttendanceRecord{
		ID:        generateID(),
		UserID:    user.ID,
		Username:  user.Username,
		Timestamp: time.Now(),
		Status:    "present",
		QRCode:    req.QRCode,
	}

	recordsMutex.Lock()
	attendanceRecords[record.ID] = record
	recordsMutex.Unlock()

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

// === Integration API Endpoints ===

// User validation - checks if user exists (internal or external)
func validateUser(userID string, token string) (*User, error) {
	authConfigMutex.RLock()
	config := externalAuthConfig
	authConfigMutex.RUnlock()

	if !config.Enabled || config.Type == "none" {
		// Use internal user management
		usersMutex.RLock()
		user, exists := users[userID]
		usersMutex.RUnlock()

		if !exists || !user.Active {
			return nil, iris.NewProblem().Status(404).Detail("User not found or inactive")
		}
		return &user, nil
	}

	// External authentication
	switch config.Type {
	case "api":
		return validateUserViaAPI(userID, token, config)
	case "jwt":
		return validateUserViaJWT(token)
	default:
		return nil, iris.NewProblem().Status(500).Detail("Unsupported auth type")
	}
}

func validateUserViaAPI(userID, token string, config ExternalAuthConfig) (*User, error) {
	// Call external API to validate user
	// This is a placeholder - implement actual HTTP call
	log.Printf("Validating user %s via external API: %s", userID, config.Endpoint)

	// Example implementation would be:
	// resp, err := http.Post(config.Endpoint + "/validate", ...)
	// Parse response and return User struct

	return nil, iris.NewProblem().Status(501).Detail("External API validation not implemented")
}

func validateUserViaJWT(token string) (*User, error) {
	// Validate JWT token and extract user info
	log.Printf("Validating user via JWT token")
	return nil, iris.NewProblem().Status(501).Detail("JWT validation not implemented")
}

// Configure external authentication
func configureExternalAuth(ctx iris.Context) {
	var config ExternalAuthConfig
	if err := ctx.ReadJSON(&config); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{"error": err.Error()})
		return
	}

	authConfigMutex.Lock()
	externalAuthConfig = config
	authConfigMutex.Unlock()

	ctx.JSON(iris.Map{
		"success": true,
		"config":  config,
		"message": "External authentication configured",
	})
}

func getExternalAuthConfig(ctx iris.Context) {
	authConfigMutex.RLock()
	config := externalAuthConfig
	authConfigMutex.RUnlock()

	ctx.JSON(iris.Map{
		"success": true,
		"config":  config,
	})
}

// Internal user management endpoints
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

	usersMutex.Lock()
	defer usersMutex.Unlock()

	// Check for duplicate ID
	if existingUser, exists := users[user.ID]; exists {
		ctx.StatusCode(iris.StatusConflict)
		ctx.JSON(iris.Map{
			"error":        "User with this ID already exists",
			"existingUser": existingUser,
		})
		return
	}

	// Check for duplicate email
	for _, existingUser := range users {
		if existingUser.Email == user.Email {
			ctx.StatusCode(iris.StatusConflict)
			ctx.JSON(iris.Map{
				"error":        "User with this email already exists",
				"existingUser": existingUser,
			})
			return
		}
	}

	user.CreatedAt = time.Now()
	user.Active = true
	users[user.ID] = user

	ctx.JSON(iris.Map{
		"success": true,
		"user":    user,
		"message": "User created successfully",
	})
}

func getUser(ctx iris.Context) {
	userID := ctx.Params().Get("id")

	usersMutex.RLock()
	user, exists := users[userID]
	usersMutex.RUnlock()

	if !exists {
		ctx.StatusCode(iris.StatusNotFound)
		ctx.JSON(iris.Map{"error": "User not found"})
		return
	}

	ctx.JSON(user)
}

func listUsers(ctx iris.Context) {
	usersMutex.RLock()
	defer usersMutex.RUnlock()

	var userList []User
	for _, user := range users {
		userList = append(userList, user)
	}

	ctx.JSON(iris.Map{
		"success": true,
		"count":   len(userList),
		"users":   userList,
	})
}

func updateUser(ctx iris.Context) {
	userID := ctx.Params().Get("id")

	var updates User
	if err := ctx.ReadJSON(&updates); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{"error": err.Error()})
		return
	}

	usersMutex.Lock()
	defer usersMutex.Unlock()

	user, exists := users[userID]
	if !exists {
		ctx.StatusCode(iris.StatusNotFound)
		ctx.JSON(iris.Map{"error": "User not found"})
		return
	}

	if updates.Username != "" {
		user.Username = updates.Username
	}
	if updates.Email != "" {
		user.Email = updates.Email
	}
	if updates.Role != "" {
		user.Role = updates.Role
	}
	if updates.Metadata != nil {
		user.Metadata = updates.Metadata
	}
	user.Active = updates.Active

	users[userID] = user

	ctx.JSON(iris.Map{
		"success": true,
		"user":    user,
	})
}

func deleteUser(ctx iris.Context) {
	userID := ctx.Params().Get("id")

	usersMutex.Lock()
	delete(users, userID)
	usersMutex.Unlock()

	ctx.JSON(iris.Map{"success": true})
}

// Sync users from external system
func syncUsers(ctx iris.Context) {
	var req struct {
		Users          []User `json:"users"`
		UpdateExisting bool   `json:"updateExisting"` // If true, update existing users
	}

	if err := ctx.ReadJSON(&req); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{"error": err.Error()})
		return
	}

	usersMutex.Lock()
	defer usersMutex.Unlock()

	synced := 0
	updated := 0
	skipped := 0
	var errors []string

	for _, user := range req.Users {
		if user.ID == "" {
			errors = append(errors, "User without ID skipped")
			skipped++
			continue
		}

		// Check if user already exists
		existingUser, exists := users[user.ID]

		if exists {
			if req.UpdateExisting {
				// Update existing user
				if user.Username != "" {
					existingUser.Username = user.Username
				}
				if user.Email != "" {
					existingUser.Email = user.Email
				}
				if user.Role != "" {
					existingUser.Role = user.Role
				}
				if user.Metadata != nil {
					existingUser.Metadata = user.Metadata
				}
				existingUser.Active = user.Active
				users[user.ID] = existingUser
				updated++
			} else {
				// Skip duplicate
				skipped++
			}
		} else {
			// Check for duplicate email
			emailExists := false
			for _, u := range users {
				if u.Email == user.Email && user.Email != "" {
					emailExists = true
					errors = append(errors, "Duplicate email for user ID "+user.ID+": "+user.Email)
					skipped++
					break
				}
			}

			if !emailExists {
				// Create new user
				user.Active = true
				if user.CreatedAt.IsZero() {
					user.CreatedAt = time.Now()
				}
				users[user.ID] = user
				synced++
			}
		}
	}

	ctx.JSON(iris.Map{
		"success":    true,
		"synced":     synced,
		"updated":    updated,
		"skipped":    skipped,
		"total":      len(req.Users),
		"errors":     errors,
		"message":    fmt.Sprintf("Synced: %d, Updated: %d, Skipped: %d", synced, updated, skipped),
	})
}

func getAttendanceRecords(ctx iris.Context) {
	userID := ctx.URLParam("userId")
	// startDate and endDate can be used for filtering in the future
	// startDate := ctx.URLParam("startDate")
	// endDate := ctx.URLParam("endDate")

	recordsMutex.RLock()
	defer recordsMutex.RUnlock()

	var filtered []AttendanceRecord
	for _, record := range attendanceRecords {
		if userID != "" && record.UserID != userID {
			continue
		}
		filtered = append(filtered, record)
	}

	ctx.JSON(iris.Map{
		"success": true,
		"count":   len(filtered),
		"records": filtered,
	})
}

func getAttendanceRecord(ctx iris.Context) {
	recordID := ctx.Params().Get("id")

	recordsMutex.RLock()
	record, exists := attendanceRecords[recordID]
	recordsMutex.RUnlock()

	if !exists {
		ctx.StatusCode(iris.StatusNotFound)
		ctx.JSON(iris.Map{"error": "Record not found"})
		return
	}

	ctx.JSON(record)
}

func createWebhook(ctx iris.Context) {
	var webhook WebhookConfig
	if err := ctx.ReadJSON(&webhook); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{"error": err.Error()})
		return
	}

	webhookID := generateID()
	webhook.Enabled = true

	webhooksMutex.Lock()
	webhooks[webhookID] = webhook
	webhooksMutex.Unlock()

	ctx.JSON(iris.Map{
		"success":   true,
		"webhookId": webhookID,
		"webhook":   webhook,
	})
}

func listWebhooks(ctx iris.Context) {
	webhooksMutex.RLock()
	defer webhooksMutex.RUnlock()

	var list []iris.Map
	for id, webhook := range webhooks {
		list = append(list, iris.Map{
			"id":      id,
			"webhook": webhook,
		})
	}

	ctx.JSON(iris.Map{
		"success":  true,
		"webhooks": list,
	})
}

func deleteWebhook(ctx iris.Context) {
	webhookID := ctx.Params().Get("id")

	webhooksMutex.Lock()
	delete(webhooks, webhookID)
	webhooksMutex.Unlock()

	ctx.JSON(iris.Map{"success": true})
}

func createAPIKey(ctx iris.Context) {
	var req struct {
		Name string `json:"name"`
	}

	if err := ctx.ReadJSON(&req); err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		ctx.JSON(iris.Map{"error": err.Error()})
		return
	}

	key := "ak_" + generateID()
	apiKey := APIKey{
		Key:       key,
		Name:      req.Name,
		CreatedAt: time.Now(),
		Enabled:   true,
	}

	apiKeysMutex.Lock()
	apiKeys[key] = apiKey
	apiKeysMutex.Unlock()

	ctx.JSON(iris.Map{
		"success": true,
		"apiKey":  apiKey,
	})
}

func listAPIKeys(ctx iris.Context) {
	apiKeysMutex.RLock()
	defer apiKeysMutex.RUnlock()

	var list []APIKey
	for _, key := range apiKeys {
		list = append(list, key)
	}

	ctx.JSON(iris.Map{
		"success": true,
		"apiKeys": list,
	})
}

func revokeAPIKey(ctx iris.Context) {
	key := ctx.Params().Get("key")

	apiKeysMutex.Lock()
	if apiKey, exists := apiKeys[key]; exists {
		apiKey.Enabled = false
		apiKeys[key] = apiKey
	}
	apiKeysMutex.Unlock()

	ctx.JSON(iris.Map{"success": true})
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func mustMarshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func main() {
	app := iris.New()

	hub = newHub()
	go hub.run()

	// Create a default API key for testing
	apiKeys["ak_test_key_12345"] = APIKey{
		Key:       "ak_test_key_12345",
		Name:      "Default Test Key",
		CreatedAt: time.Now(),
		Enabled:   true,
	}

	// Create some default users for testing
	users["user1"] = User{
		ID:        "user1",
		Username:  "John Doe",
		Email:     "john@example.com",
		Role:      "employee",
		Active:    true,
		CreatedAt: time.Now(),
	}
	users["user2"] = User{
		ID:        "user2",
		Username:  "Jane Smith",
		Email:     "jane@example.com",
		Role:      "employee",
		Active:    true,
		CreatedAt: time.Now(),
	}
	users["admin1"] = User{
		ID:        "admin1",
		Username:  "Admin User",
		Email:     "admin@example.com",
		Role:      "admin",
		Active:    true,
		CreatedAt: time.Now(),
	}

	// WebSocket upgrader configuration
	var wsUpgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins for development
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

	// WebSocket endpoint using gorilla/websocket
	app.Get("/ws", func(ctx iris.Context) {
		role := ctx.URLParam("role")
		userID := ctx.URLParam("userId")

		if role == "" || userID == "" {
			ctx.StatusCode(iris.StatusBadRequest)
			ctx.JSON(iris.Map{"error": "role and userId parameters required"})
			return
		}

		// Upgrade HTTP connection to WebSocket
		conn, err := wsUpgrader.Upgrade(ctx.ResponseWriter(), ctx.Request(), nil)
		if err != nil {
			log.Printf("WebSocket upgrade error: %v", err)
			return
		}

		clientID := generateID()
		client := &Client{
			ID:     clientID,
			UserID: userID,
			Role:   role,
			Conn:   conn,
			Send:   make(chan []byte, 256),
			Hub:    hub,
		}

		hub.register <- client

		// Start client goroutines
		go client.writePump()
		go client.readPump()
	})

	// Public API routes (for frontend)
	api := app.Party("/api")
	{
		qr := api.Party("/qr")
		{
			qr.Post("/generate", generateQRCode)
			qr.Post("/scan", scanQRCode)
		}
	}

	// Integration API routes (requires API key)
	integrationAPI := app.Party("/api/v1", apiKeyAuth)
	{
		// Attendance endpoints
		integrationAPI.Get("/attendance", getAttendanceRecords)
		integrationAPI.Get("/attendance/{id}", getAttendanceRecord)

		// User management endpoints
		integrationAPI.Post("/users", createUser)
		integrationAPI.Get("/users", listUsers)
		integrationAPI.Get("/users/{id}", getUser)
		integrationAPI.Put("/users/{id}", updateUser)
		integrationAPI.Delete("/users/{id}", deleteUser)
		integrationAPI.Post("/users/sync", syncUsers)

		// External authentication configuration
		integrationAPI.Post("/auth/config", configureExternalAuth)
		integrationAPI.Get("/auth/config", getExternalAuthConfig)

		// Webhook management
		integrationAPI.Post("/webhooks", createWebhook)
		integrationAPI.Get("/webhooks", listWebhooks)
		integrationAPI.Delete("/webhooks/{id}", deleteWebhook)

		// API Key management
		integrationAPI.Post("/api-keys", createAPIKey)
		integrationAPI.Get("/api-keys", listAPIKeys)
		integrationAPI.Delete("/api-keys/{key}", revokeAPIKey)
	}

	log.Println("Server starting on :8080")
	log.Println("Default API Key: ak_test_key_12345")
	app.Listen(":8080")
}
