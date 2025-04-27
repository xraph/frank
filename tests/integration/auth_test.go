package integration

// import (
// 	"bytes"
// 	"context"
// 	"encoding/json"
// 	"net/http"
// 	"net/http/httptest"
// 	"testing"
// 	"time"
//
// 	"github.com/juicycleff/frank/config"
// 	"github.com/juicycleff/frank/ent"
// 	entuser "github.com/juicycleff/frank/ent/user"
// 	"github.com/juicycleff/frank/internal/auth/session"
// 	"github.com/juicycleff/frank/internal/handlers"
// 	"github.com/juicycleff/frank/pkg/crypto"
// 	"github.com/juicycleff/frank/pkg/logging"
// 	user2 "github.com/juicycleff/frank/user"
// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/require"
// )
//
// func TestLoginEndpoint(t *testing.T) {
// 	// Setup test dependencies
// 	cfg := setupTestConfig()
// 	ctx := context.Background()
// 	client := setupTestDatabase(t)
// 	defer client.Close()
// 	logger := logging.GetLogger()
// 	sessionMgr := session.NewManager(client, cfg, logger, nil)
// 	userSvc := setupUserService(client, cfg, logger)
//
// 	// Create a test user
//
// 	testUser, err := client.User.Create().
// 		SetEmail("test@example.com").
// 		SetFirstName("Test").
// 		SetLastName("User").
// 		SetEmailVerified(true).
// 		Save(ctx)
// 	require.NoError(t, err)
//
// 	// Setup handler
// 	authHandler := handlers.NewAuthHandler(userSvc, cfg, logger, sessionMgr)
//
// 	// Create test request
// 	loginData := map[string]interface{}{
// 		"email":    testUser.Email,
// 		// "password": password,
// 	}
// 	jsonData, err := json.Marshal(loginData)
// 	require.NoError(t, err)
//
// 	req, err := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonData))
// 	require.NoError(t, err)
// 	req.Header.Set("Content-Type", "application/json")
//
// 	// Execute request
// 	rr := httptest.NewRecorder()
// 	handler := http.HandlerFunc(authHandler.Login)
// 	handler.ServeHTTP(rr, req)
//
// 	// Check response
// 	assert.Equal(t, http.StatusOK, rr.Code)
//
// 	// Parse response
// 	var loginResponse map[string]interface{}
// 	err = json.Unmarshal(rr.Body.Bytes(), &loginResponse)
// 	require.NoError(t, err)
//
// 	// Validate response fields
// 	assert.Contains(t, loginResponse, "user")
// 	assert.Contains(t, loginResponse, "token")
// 	assert.Contains(t, loginResponse, "refresh_token")
// 	assert.Contains(t, loginResponse, "expires_at")
//
// 	// Validate the user in the response is correct
// 	user := loginResponse["user"].(map[string]interface{})
// 	assert.Equal(t, testUser.ID, user["id"])
// 	assert.Equal(t, testUser.Email, user["email"])
// }
//
// func TestRegisterEndpoint(t *testing.T) {
// 	// Setup test dependencies
// 	cfg := setupTestConfig()
// 	client := setupTestDatabase(t)
// 	defer client.Close()
// 	logger := logging.GetLogger()
// 	sessionMgr := session.NewManager(client, cfg, logger, nil)
// 	userSvc := setupUserService(client, cfg, logger)
//
// 	// Setup handler
// 	authHandler := handlers.NewAuthHandler(userSvc, cfg, logger, sessionMgr)
//
// 	// Create test request
// 	email := "newuser@example.com"
// 	registerData := map[string]interface{}{
// 		"email":      email,
// 		"password":   "securePassword123!",
// 		"first_name": "New",
// 		"last_name":  "User",
// 	}
// 	jsonData, err := json.Marshal(registerData)
// 	require.NoError(t, err)
//
// 	req, err := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(jsonData))
// 	require.NoError(t, err)
// 	req.Header.Set("Content-Type", "application/json")
//
// 	// Execute request
// 	rr := httptest.NewRecorder()
// 	handler := http.HandlerFunc(authHandler.Register)
// 	handler.ServeHTTP(rr, req)
//
// 	// Check response
// 	assert.Equal(t, http.StatusCreated, rr.Code)
//
// 	// Parse response
// 	var registerResponse map[string]interface{}
// 	err = json.Unmarshal(rr.Body.Bytes(), &registerResponse)
// 	require.NoError(t, err)
//
// 	// Validate response
// 	assert.Contains(t, registerResponse, "user")
//
// 	// Validate the user was actually created in the database
// 	ctx := context.Background()
// 	usr, err := client.User.Query().Where(
// 		entuser.EmailEQ(email),
// 	).Only(ctx)
//
// 	require.NoError(t, err)
// 	assert.Equal(t, email, usr.Email)
// 	assert.Equal(t, "New", usr.FirstName)
// 	assert.Equal(t, "User", usr.LastName)
// }
//
// func TestPasswordResetFlow(t *testing.T) {
// 	// Setup test dependencies
// 	cfg := setupTestConfig()
// 	ctx := context.Background()
// 	client := setupTestDatabase(t)
// 	defer client.Close()
// 	logger := logging.GetLogger()
// 	sessionMgr := session.NewManager(client, cfg, logger, nil)
// 	userSvc := setupUserService(client, cfg, logger)
//
// 	// Create a test user
// 	// password := "originalPassword123!"
// 	// hashedPassword, err := crypto.HashPassword(password)
// 	// require.NoError(t, err)
//
// 	testUser, err := client.User.Create().
// 		SetEmail("resettest@example.com").
// 		// SetPassword(hashedPassword).
// 		SetFirstName("Reset").
// 		SetLastName("User").
// 		SetEmailVerified(true).
// 		Save(ctx)
// 	require.NoError(t, err)
//
// 	// Setup handler
// 	authHandler := handlers.NewAuthHandler(userSvc, cfg, logger, sessionMgr)
//
// 	// Step 1: Initiate forgot password
// 	forgotData := map[string]interface{}{
// 		"email": testUser.Email,
// 	}
// 	jsonData, err := json.Marshal(forgotData)
// 	require.NoError(t, err)
//
// 	req, err := http.NewRequest("POST", "/api/v1/auth/forgot-password", bytes.NewBuffer(jsonData))
// 	require.NoError(t, err)
// 	req.Header.Set("Content-Type", "application/json")
//
// 	rr := httptest.NewRecorder()
// 	handler := http.HandlerFunc(authHandler.ForgotPassword)
// 	handler.ServeHTTP(rr, req)
//
// 	// Check response
// 	assert.Equal(t, http.StatusAccepted, rr.Code)
//
// 	// Manually create a verification token for testing
// 	verification, err := client.Verification.Create().
// 		SetUserID(testUser.ID).
// 		SetType("password_reset").
// 		SetToken("test_reset_token").
// 		SetExpiresAt(time.Now().Add(24 * time.Hour)).
// 		SetEmail(testUser.Email).
// 		Save(ctx)
// 	require.NoError(t, err)
//
// 	// Step 2: Reset password with token
// 	resetData := map[string]interface{}{
// 		"token":        verification.Token,
// 		"new_password": "newSecurePassword456!",
// 	}
// 	jsonData, err = json.Marshal(resetData)
// 	require.NoError(t, err)
//
// 	req, err = http.NewRequest("POST", "/api/v1/auth/reset-password", bytes.NewBuffer(jsonData))
// 	require.NoError(t, err)
// 	req.Header.Set("Content-Type", "application/json")
//
// 	rr = httptest.NewRecorder()
// 	handler = http.HandlerFunc(authHandler.ResetPassword)
// 	handler.ServeHTTP(rr, req)
//
// 	// Check response
// 	assert.Equal(t, http.StatusOK, rr.Code)
//
// 	// Verify the password was changed by trying to log in with the new password
// 	loginData := map[string]interface{}{
// 		"email":    testUser.Email,
// 		"password": "newSecurePassword456!",
// 	}
// 	jsonData, err = json.Marshal(loginData)
// 	require.NoError(t, err)
//
// 	req, err = http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonData))
// 	require.NoError(t, err)
// 	req.Header.Set("Content-Type", "application/json")
//
// 	rr = httptest.NewRecorder()
// 	handler = http.HandlerFunc(authHandler.Login)
// 	handler.ServeHTTP(rr, req)
//
// 	// The login should succeed with the new password
// 	assert.Equal(t, http.StatusOK, rr.Code)
// }
//
// func TestRefreshToken(t *testing.T) {
// 	// Setup test dependencies
// 	cfg := setupTestConfig()
// 	ctx := context.Background()
// 	client := setupTestDatabase(t)
// 	defer client.Close()
// 	logger := logging.GetLogger()
// 	sessionMgr := session.NewManager(client, cfg, logger, nil)
// 	userSvc := setupUserService(client, cfg, logger)
//
// 	// Create a test user
// 	testUser, err := client.User.Create().
// 		SetEmail("refresh@example.com").
// 		// SetPassword("password"). // Doesn't matter for this test
// 		SetFirstName("Refresh").
// 		SetLastName("User").
// 		SetEmailVerified(true).
// 		Save(ctx)
// 	require.NoError(t, err)
//
// 	// Create JWTConfig
// 	jwtConfig := &crypto.JWTConfig{
// 		SigningMethod: cfg.Auth.TokenSigningMethod,
// 		SignatureKey:  []byte(cfg.Auth.TokenSecretKey),
// 		ValidationKey: []byte(cfg.Auth.TokenSecretKey),
// 		Issuer:        cfg.Auth.TokenIssuer,
// 		Audience:      cfg.Auth.TokenAudience,
// 	}
//
// 	// Create refresh token
// 	refreshClaims := map[string]interface{}{
// 		"user_id":    testUser.ID,
// 		"email":      testUser.Email,
// 		"token_type": "refresh",
// 	}
// 	refreshToken, err := jwtConfig.GenerateToken(testUser.ID, refreshClaims, cfg.Auth.RefreshTokenDuration)
// 	require.NoError(t, err)
//
// 	// Setup handler
// 	authHandler := handlers.NewAuthHandler(userSvc, cfg, logger, sessionMgr)
//
// 	// Create refresh token request
// 	refreshData := map[string]interface{}{
// 		"refresh_token": refreshToken,
// 	}
// 	jsonData, err := json.Marshal(refreshData)
// 	require.NoError(t, err)
//
// 	req, err := http.NewRequest("POST", "/api/v1/auth/refresh", bytes.NewBuffer(jsonData))
// 	require.NoError(t, err)
// 	req.Header.Set("Content-Type", "application/json")
//
// 	// Execute request
// 	rr := httptest.NewRecorder()
// 	handler := http.HandlerFunc(authHandler.RefreshToken)
// 	handler.ServeHTTP(rr, req)
//
// 	// Check response
// 	assert.Equal(t, http.StatusOK, rr.Code)
//
// 	// Parse response
// 	var refreshResponse map[string]interface{}
// 	err = json.Unmarshal(rr.Body.Bytes(), &refreshResponse)
// 	require.NoError(t, err)
//
// 	// Validate response fields
// 	assert.Contains(t, refreshResponse, "token")
// 	assert.Contains(t, refreshResponse, "refresh_token")
// 	assert.Contains(t, refreshResponse, "expires_at")
// }
//
// // Setup helper functions
// func setupTestConfig() *config.Config {
// 	return &config.Config{
// 		Auth: config.AuthConfig{
// 			TokenSecretKey:       "test-secret-key",
// 			TokenSigningMethod:   "HS256",
// 			TokenIssuer:          "frank",
// 			TokenAudience:        []string{"frank-api"},
// 			AccessTokenDuration:  15 * time.Minute,
// 			RefreshTokenDuration: 7 * 24 * time.Hour,
// 			SessionDuration:      24 * time.Hour,
// 			RememberMeDuration:   30 * 24 * time.Hour,
// 		},
// 	}
// }
//
// func setupTestDatabase(t *testing.T) *ent.Client {
// 	// Create an in-memory SQLite database for testing
// 	client, err := ent.Open("sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
// 	require.NoError(t, err)
//
// 	// Run the auto migration tool
// 	err = client.Schema.Create(context.Background())
// 	require.NoError(t, err)
//
// 	return client
// }
//
// func setupUserService(client *ent.Client, cfg *config.Config, logger logging.Logger) user2.Service {
// 	// Setup the user repository
// 	repo := user2.NewRepository(client)
//
// 	// Create the user service
// 	return user2.NewService(repo, cfg, logger)
// }
