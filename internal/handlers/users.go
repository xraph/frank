package handlers

import (
	"fmt"
	"net/http"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/internal/user"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
)

// UserHandler handles user operations
type UserHandler struct {
	userService user.Service
	config      *config.Config
	logger      logging.Logger
}

// NewUserHandler creates a new user handler
func NewUserHandler(
	userService user.Service,
	config *config.Config,
	logger logging.Logger,
) *UserHandler {
	return &UserHandler{
		userService: userService,
		config:      config,
		logger:      logger,
	}
}

// UpdateUserInput represents input for updating a user
type UpdateUserInput struct {
	FirstName       *string                `json:"first_name,omitempty"`
	LastName        *string                `json:"last_name,omitempty"`
	PhoneNumber     *string                `json:"phone_number,omitempty"`
	ProfileImageURL *string                `json:"profile_image_url,omitempty"`
	Locale          *string                `json:"locale,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateCurrentUser handles updating the current user
func (h *UserHandler) UpdateCurrentUser(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := middleware.GetUserID(r)
	if !ok {
		utils.RespondError(w, errors.New(errors.CodeUnauthorized, "not authenticated"))
		return
	}

	// Parse input
	var input UpdateUserInput
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Map to service input
	updateInput := user.UpdateUserInput{
		FirstName:       input.FirstName,
		LastName:        input.LastName,
		PhoneNumber:     input.PhoneNumber,
		ProfileImageURL: input.ProfileImageURL,
		Locale:          input.Locale,
		Metadata:        input.Metadata,
	}

	// Update user
	updatedUser, err := h.userService.Update(r.Context(), userID, updateInput)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return updated user
	utils.RespondJSON(w, http.StatusOK, updatedUser)
}

// ListUsers handles listing users with pagination
func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	offset := utils.ParseQueryInt(r, "offset", 0)
	limit := utils.ParseQueryInt(r, "limit", 20)
	search := r.URL.Query().Get("search")
	organizationID := r.URL.Query().Get("organization_id")

	// Create list params
	params := user.ListParams{
		Offset:         offset,
		Limit:          limit,
		Search:         search,
		OrganizationID: organizationID,
	}

	// List users
	users, total, err := h.userService.List(r.Context(), params)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return response with pagination
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"data":  users,
		"total": total,
		"pagination": map[string]interface{}{
			"offset": offset,
			"limit":  limit,
			"total":  total,
		},
	})
}

// GetUser handles retrieving a user by ID
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	// Get user ID from path
	userID := utils.GetPathVar(r, "id")
	if userID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "user ID is required"))
		return
	}

	// Get user
	user, err := h.userService.Get(r.Context(), userID)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return user
	utils.RespondJSON(w, http.StatusOK, user)
}

// CreateUser handles creating a new user
func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	// Parse input
	var input user.CreateUserInput
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Create user
	newUser, err := h.userService.Create(r.Context(), input)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return created user
	utils.RespondJSON(w, http.StatusCreated, newUser)
}

// UpdateUser handles updating a user
func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	// Get user ID from path
	userID := utils.GetPathVar(r, "id")
	if userID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "user ID is required"))
		return
	}

	// Parse input
	var input user.UpdateUserInput
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Update user
	updatedUser, err := h.userService.Update(r.Context(), userID, input)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return updated user
	utils.RespondJSON(w, http.StatusOK, updatedUser)
}

// DeleteUser handles deleting a user
func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	// Get user ID from path
	userID := utils.GetPathVar(r, "id")
	if userID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "user ID is required"))
		return
	}

	// Delete user
	err := h.userService.Delete(r.Context(), userID)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return success
	utils.RespondJSON(w, http.StatusNoContent, nil)
}

// GetUserSessions handles retrieving a user's sessions
func (h *UserHandler) GetUserSessions(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := middleware.GetUserID(r)
	if !ok {
		utils.RespondError(w, errors.New(errors.CodeUnauthorized, "not authenticated"))
		return
	}
	fmt.Println(userID)

	// Get sessions (implementation depends on session manager)
	// For now, return empty array
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"data": []interface{}{},
	})
}

// DeleteUserSession handles deleting a user's session
func (h *UserHandler) DeleteUserSession(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := middleware.GetUserID(r)
	if !ok {
		utils.RespondError(w, errors.New(errors.CodeUnauthorized, "not authenticated"))
		return
	}
	fmt.Println(userID)

	// Get session ID from path
	sessionID := utils.GetPathVar(r, "id")
	if sessionID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "session ID is required"))
		return
	}

	// Delete session (implementation depends on session manager)
	// For now, return success
	utils.RespondJSON(w, http.StatusNoContent, nil)
}

// SetupRoutes sets up the user routes
func (h *UserHandler) SetupRoutes(router *http.ServeMux) {
	router.HandleFunc("/api/v1/users/me", h.UpdateCurrentUser)
	router.HandleFunc("/api/v1/users/me/sessions", h.GetUserSessions)
	router.HandleFunc("/api/v1/users/me/sessions/{id}", h.DeleteUserSession)
	router.HandleFunc("/api/v1/users", h.ListUsers)
	router.HandleFunc("/api/v1/users/{id}", h.GetUser)
	router.HandleFunc("/api/v1/users", h.CreateUser)
	router.HandleFunc("/api/v1/users/{id}", h.UpdateUser)
	router.HandleFunc("/api/v1/users/{id}", h.DeleteUser)
}

// UpdateCurrentUser handles updating the current user API endpoint
func UpdateCurrentUser(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).User.UpdateCurrentUser(w, r)
}

// GetUserSessions handles retrieving user sessions API endpoint
func GetUserSessions(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).User.GetUserSessions(w, r)
}

// DeleteUserSession handles deleting a user session API endpoint
func DeleteUserSession(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).User.DeleteUserSession(w, r)
}

// ListUsers handles listing users API endpoint
func ListUsers(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).User.ListUsers(w, r)
}

// GetUser handles retrieving a user API endpoint
func GetUser(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).User.GetUser(w, r)
}

// CreateUser handles creating a user API endpoint
func CreateUser(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).User.CreateUser(w, r)
}

// UpdateUser handles updating a user API endpoint
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).User.UpdateUser(w, r)
}

// DeleteUser handles deleting a user API endpoint
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).User.DeleteUser(w, r)
}
