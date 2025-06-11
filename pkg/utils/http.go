package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// SessionStore is a shared session store for the application
var SessionStore sessions.Store

// Response represents a standardized API response
type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   interface{} `json:"error,omitempty"`
}

// PageInfo represents pagination metadata including total items, current page, items per page, and total pages.
type PageInfo struct {
	TotalCount int `json:"totalCount"`
	PageNumber int `json:"pageNumber"`
	PageSize   int `json:"pageSize"`
	TotalPages int `json:"totalPages"`
}

// PagedResponse represents a paginated response containing a list of items and associated pagination metadata.
type PagedResponse struct {
	Items    interface{} `json:"items,omitempty"`
	PageInfo PageInfo    `json:"pageInfo,omitempty"`
}

// RespondPagedJSON sends a JSON response
func RespondPagedJSON(w http.ResponseWriter, status int, data PagedResponse) {
	response := Response{
		Success: status >= 200 && status < 400,
		Data:    data,
	}

	RespondWithJSON(w, status, response)
}

// RespondJSON sends a JSON response
func RespondJSON(w http.ResponseWriter, status int, data interface{}) {
	response := Response{
		Success: status >= 200 && status < 400,
		Data:    data,
	}

	RespondWithJSON(w, status, response)
}

// RespondWithJSON sends a raw JSON response
func RespondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if data == nil {
		return
	}

	encoder := json.NewEncoder(w)
	if err := encoder.Encode(data); err != nil {
		// Log the error but don't modify the response
		logger := logging.GetLogger()
		logger.Error("Failed to encode response", logging.Error(err))
	}
}

// RespondError sends an error response
func RespondError(w http.ResponseWriter, err error) {
	var status int
	var errorResp interface{}

	if e, ok := err.(*errors.Error); ok {
		status = e.StatusCode
		errorResp = errors.NewErrorResponse(e)
	} else {
		status = http.StatusInternalServerError
		errorResp = errors.NewErrorResponse(errors.New(errors.CodeInternalServer, err.Error()))
	}

	response := Response{
		Success: false,
		Error:   errorResp,
	}

	RespondWithJSON(w, status, response)
}

// DecodeJSON decodes a JSON request body
func DecodeJSON(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return errors.New(errors.CodeBadRequest, "request body is empty")
	}

	defer r.Body.Close()

	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		if err == io.EOF {
			return errors.New(errors.CodeBadRequest, "request body is empty")
		}
		return errors.Wrap(err, errors.CodeBadRequest, "invalid JSON format")
	}

	return nil
}

// GetIPAddress extracts the client IP address from a request
func GetIPAddress(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies)
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		// X-Forwarded-For can be a comma-separated list; use the first address
		ips := strings.Split(xForwardedFor, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header next
	xRealIP := r.Header.Get("X-Real-IP")
	if xRealIP != "" {
		return xRealIP
	}

	// Fall back to remote address
	return strings.Split(r.RemoteAddr, ":")[0]
}

// GetUserAgent extracts the user agent from a request
func GetUserAgent(r *http.Request) string {
	return r.Header.Get("User-Agent")
}

// GetRequestID extracts the request ID from a request
func GetRequestID(r *http.Request) string {
	return r.Header.Get("X-Request-ID")
}

// GetContentType extracts the content type from a request
func GetContentType(r *http.Request) string {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		return "application/octet-stream"
	}
	return strings.Split(contentType, ";")[0]
}

// GetAccept extracts the accept header from a request
func GetAccept(r *http.Request) string {
	return r.Header.Get("Accept")
}

// GetBearerToken extracts the bearer token from a request
func GetBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New(errors.CodeUnauthorized, "authorization header is missing")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", errors.New(errors.CodeUnauthorized, "authorization header format must be Bearer {token}")
	}

	return parts[1], nil
}

// GetBasicAuth extracts the basic auth credentials from a request
func GetBasicAuth(r *http.Request) (username, password string, ok bool) {
	return r.BasicAuth()
}

// ParseQueryParams parses query parameters into a struct
func ParseQueryParams(r *http.Request, v interface{}) error {
	if err := r.ParseForm(); err != nil {
		return errors.Wrap(err, errors.CodeBadRequest, "failed to parse query parameters")
	}

	decoder := json.NewDecoder(strings.NewReader(r.Form.Encode()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return errors.Wrap(err, errors.CodeBadRequest, "failed to decode query parameters")
	}

	return nil
}

// SetCookie sets a cookie with secure defaults
func SetCookie(w http.ResponseWriter, name, value string, maxAge int, path string, secure bool) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

// DeleteCookie deletes a cookie
func DeleteCookie(w http.ResponseWriter, name, path string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

// GetOrigin extracts the origin from a request
func GetOrigin(r *http.Request) string {
	return r.Header.Get("Origin")
}

// IsAjaxRequest checks if a request is an AJAX request
func IsAjaxRequest(r *http.Request) bool {
	return r.Header.Get("X-Requested-With") == "XMLHttpRequest"
}

// BuildURL builds a URL with query parameters
func BuildURL(baseURL string, queryParams map[string]string) string {
	if len(queryParams) == 0 {
		return baseURL
	}

	var queryStrings []string
	for key, value := range queryParams {
		queryStrings = append(queryStrings, fmt.Sprintf("%s=%s", key, value))
	}

	if strings.Contains(baseURL, "?") {
		return baseURL + "&" + strings.Join(queryStrings, "&")
	}
	return baseURL + "?" + strings.Join(queryStrings, "&")
}

// InitSessionStore initializes the session store with the provided secret
func InitSessionStore(cfg *config.Config) {
	// Use the session secret key from config
	SessionStore = sessions.NewCookieStore([]byte(cfg.Auth.SessionSecretKey))
}

// InitSessionStoreWithStore initializes the session store with the provided secret
func InitSessionStoreWithStore(store sessions.Store) {
	// Use the session secret key from config
	SessionStore = store
}

// GetSession retrieves the current session or creates a new one
func GetSession(r *http.Request, cfg *config.Config) (*sessions.Session, error) {
	// Initialize store if not already done
	if SessionStore == nil {
		InitSessionStore(cfg)
	}

	// Use a consistent session name
	const sessionName = "frank_session"

	// Get the session
	sess, err := SessionStore.Get(r, sessionName)
	if err != nil {
		// If there's an error (like session decoding fails),
		// create a new empty session
		sess, _ = SessionStore.New(r, sessionName)
	}

	return sess, nil
}

// GetSessionValue gets a typed value from the session
func GetSessionValue[T any](r *http.Request, cfg *config.Config, key string) (T, bool) {
	var defaultValue T

	session, err := GetSession(r, cfg)
	if err != nil {
		return defaultValue, false
	}

	if val, ok := session.Values[key]; ok {
		if typedVal, ok := val.(T); ok {
			return typedVal, true
		}
	}

	return defaultValue, false
}

// SetSessionValue sets a value in the session and saves it
func SetSessionValue(w http.ResponseWriter, r *http.Request, cfg *config.Config, key string, value interface{}) error {
	session, err := GetSession(r, cfg)
	if err != nil {
		return err
	}

	session.Values[key] = value
	return session.Save(r, w)
}

// ClearSession removes all values from the session
func ClearSession(w http.ResponseWriter, r *http.Request, cfg *config.Config) error {
	session, err := GetSession(r, cfg)
	if err != nil {
		return err
	}

	// Clear session
	for key := range session.Values {
		delete(session.Values, key)
	}

	// Force immediate expiration
	session.Options.MaxAge = -1

	return session.Save(r, w)
}

// IsAuthenticated checks if the current session has an authenticated user
func IsAuthenticated(r *http.Request, cfg *config.Config) bool {
	userID, ok := GetSessionValue[string](r, cfg, "user_id")
	return ok && userID != ""
}

// GetUserID gets the current user ID from the session
func GetUserID(r *http.Request, cfg *config.Config) (string, bool) {
	return GetSessionValue[string](r, cfg, "user_id")
}

// GetOrganizationID gets the current organization ID from the session
func GetOrganizationID(r *http.Request, cfg *config.Config) (string, bool) {
	return GetSessionValue[string](r, cfg, "organization_id")
}

// parseSameSite converts a string SameSite value to http.SameSite
func parseSameSite(sameSite string) http.SameSite {
	switch strings.ToLower(sameSite) {
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode // Default to Lax mode
	}
}

// GetRealIP extracts the real client IP address from request headers
func GetRealIP(r *http.Request) string {
	// Check for X-Forwarded-For header
	if xForwardedFor := r.Header.Get("X-Forwarded-For"); xForwardedFor != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(xForwardedFor, ",")
		ip := strings.TrimSpace(ips[0])
		if ip != "" {
			return ip
		}
	}

	// Check for X-Real-IP header
	if xRealIP := r.Header.Get("X-Real-IP"); xRealIP != "" {
		return xRealIP
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// RequestInfo contains information about an HTTP request
type RequestInfo struct {
	Method      string
	Path        string
	RemoteAddr  string
	UserAgent   string
	Referrer    string
	ContentType string
	StatusCode  int
	Timestamp   time.Time
}

// GetRequestInfo extracts common request information
func GetRequestInfo(r *http.Request, statusCode int) RequestInfo {
	return RequestInfo{
		Method:      r.Method,
		Path:        r.URL.Path,
		RemoteAddr:  GetRealIP(r),
		UserAgent:   r.UserAgent(),
		Referrer:    r.Referer(),
		ContentType: r.Header.Get("Content-Type"),
		StatusCode:  statusCode,
		Timestamp:   time.Now(),
	}
}

// URLParamRegex is used to extract URL parameters from the pattern.
var URLParamRegex = regexp.MustCompile(`\{([^{}]+)\}`)

// GetPathVar gets a path variable from a request using Chi router.
func GetPathVar(r *http.Request, name string) string {
	return chi.URLParam(r, name)
}

// GetPathVarInt gets a path variable from a request as int.
func GetPathVarInt(r *http.Request, name string) (int, error) {
	str := GetPathVar(r, name)
	if str == "" {
		return 0, errors.New(errors.CodeInvalidInput, "path variable is empty")
	}

	val, err := strconv.Atoi(str)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInvalidInput, "invalid integer format")
	}

	return val, nil
}

// GetPathVarUUID gets a path variable from a request as UUID.
func GetPathVarUUID(r *http.Request, name string) (uuid.UUID, error) {
	str := GetPathVar(r, name)
	if str == "" {
		return uuid.Nil, errors.New(errors.CodeInvalidInput, "path variable is empty")
	}

	id, err := uuid.Parse(str)
	if err != nil {
		return uuid.Nil, errors.Wrap(err, errors.CodeInvalidInput, "invalid UUID format")
	}

	return id, nil
}

// GetQueryParam gets a query parameter from a request.
func GetQueryParam(r *http.Request, name string) string {
	return r.URL.Query().Get(name)
}

// GetQueryParamInt gets a query parameter from a request as int.
func GetQueryParamInt(r *http.Request, name string, defaultValue int) int {
	str := GetQueryParam(r, name)
	if str == "" {
		return defaultValue
	}

	val, err := strconv.Atoi(str)
	if err != nil {
		return defaultValue
	}

	return val
}

// GetQueryParamBool gets a query parameter from a request as bool.
func GetQueryParamBool(r *http.Request, name string, defaultValue bool) bool {
	str := GetQueryParam(r, name)
	if str == "" {
		return defaultValue
	}

	str = strings.ToLower(str)
	return str == "true" || str == "1" || str == "yes" || str == "y"
}

// GetQueryParamArray gets a query parameter from a request as array of strings.
func GetQueryParamArray(r *http.Request, name string) []string {
	values := r.URL.Query()[name]
	if len(values) == 0 {
		return []string{}
	}

	// If it's a comma-separated list in a single parameter
	if len(values) == 1 && strings.Contains(values[0], ",") {
		return strings.Split(values[0], ",")
	}

	return values
}

// SetContextValue sets a value in the request context.
func SetContextValue(r *http.Request, key, value interface{}) *http.Request {
	ctx := context.WithValue(r.Context(), key, value)
	return r.WithContext(ctx)
}

// GetContextValue gets a value from the request context.
func GetContextValue(r *http.Request, key interface{}) interface{} {
	return r.Context().Value(key)
}

// RedirectToURL redirects to the specified URL.
func RedirectToURL(w http.ResponseWriter, r *http.Request, redirectURL string, status int) {
	if status == 0 {
		status = http.StatusFound
	}

	http.Redirect(w, r, redirectURL, status)
}

// GetAPIKey extracts the API key from the X-API-Key header or API-Key query parameter.
func GetAPIKey(r *http.Request) (string, error) {
	// Try to get from header first
	apiKey := r.Header.Get("X-API-Key")
	if apiKey != "" {
		return apiKey, nil
	}

	// Try to get from Authorization header using Bearer scheme
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimPrefix(auth, "Bearer "), nil
	}

	// Try to get from query parameter
	apiKey = r.URL.Query().Get("api_key")
	if apiKey != "" {
		return apiKey, nil
	}

	return "", errors.New(errors.CodeUnauthorized, "API key is missing")
}

// MatchPath checks if a path matches a pattern.
func MatchPath(pattern, path string) bool {
	// Convert Chi-style route pattern to a regex pattern
	regexPattern := URLParamRegex.ReplaceAllString(pattern, `([^/]+)`)
	regexPattern = "^" + regexPattern + "$"

	// Create a regex from the pattern
	regex, err := regexp.Compile(regexPattern)
	if err != nil {
		return false
	}

	// Match the path against the regex
	return regex.MatchString(path)
}

// ExtractPathVars extracts path variables from a path using a pattern.
func ExtractPathVars(pattern, path string) map[string]string {
	params := make(map[string]string)

	// Extract parameter names from the pattern
	paramNames := URLParamRegex.FindAllStringSubmatch(pattern, -1)

	// Convert the pattern to a regex with capturing groups
	regexPattern := URLParamRegex.ReplaceAllString(pattern, "([^/]+)")
	regexPattern = "^" + regexPattern + "$"

	// Create a regex from the pattern
	regex, err := regexp.Compile(regexPattern)
	if err != nil {
		return params
	}

	// Extract parameter values from the path
	matches := regex.FindStringSubmatch(path)
	if len(matches) > 1 {
		for i, name := range paramNames {
			if i < len(matches)-1 {
				params[name[1]] = matches[i+1]
			}
		}
	}

	return params
}

// CheckOrigin checks if the origin is allowed.
func CheckOrigin(r *http.Request, allowedOrigins []string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}

	// Allow all origins if the list is empty or contains "*"
	if len(allowedOrigins) == 0 || containsString(allowedOrigins, "*") {
		return true
	}

	return containsString(allowedOrigins, origin)
}

// containsString checks if a string slice contains a string.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// GetReferringHost extracts the host from the Referer header.
func GetReferringHost(r *http.Request) string {
	referer := r.Header.Get("Referer")
	if referer == "" {
		return ""
	}

	u, err := url.Parse(referer)
	if err != nil {
		return ""
	}

	return u.Host
}

// IsJSONRequest checks if the request wants JSON response.
func IsJSONRequest(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json")
}

// GetAuthUserID gets the authenticated user ID from the request context.
func GetAuthUserID(r *http.Request, cfg *config.Config) (string, error) {
	// Try to get from context
	if userID, ok := r.Context().Value("user_id").(string); ok && userID != "" {
		return userID, nil
	}

	// Try to get from cookie session
	session, err := GetSession(r, cfg)
	if err != nil {
		return "", errors.New(errors.CodeUnauthorized, "not authenticated")
	}

	userID, ok := session.Values["user_id"].(string)
	if !ok || userID == "" {
		return "", errors.New(errors.CodeUnauthorized, "not authenticated")
	}

	return userID, nil
}

// GetAuthOrganizationID gets the authenticated organization ID from the request context.
func GetAuthOrganizationID(r *http.Request, cfg *config.Config) (string, error) {
	// Try to get from context
	if orgID, ok := r.Context().Value("organization_id").(string); ok && orgID != "" {
		return orgID, nil
	}

	// Try to get from cookie session
	session, err := GetSession(r, cfg)
	if err != nil {
		return "", errors.New(errors.CodeUnauthorized, "not authenticated")
	}

	orgID, ok := session.Values["organization_id"].(string)
	if !ok || orgID == "" {
		return "", errors.New(errors.CodeInvalidInput, "no organization selected")
	}

	return orgID, nil
}

// GetAuthAccessToken gets the authenticated user's access token from the request context.
func GetAuthAccessToken(r *http.Request, cfg *config.Config) (string, error) {
	// Try to get from context
	if token, ok := r.Context().Value("access_token").(string); ok && token != "" {
		return token, nil
	}

	// Try to get from cookie session
	session, err := GetSession(r, cfg)
	if err != nil {
		return "", errors.New(errors.CodeUnauthorized, "not authenticated")
	}

	token, ok := session.Values["token"].(string)
	if !ok || token == "" {
		return "", errors.New(errors.CodeUnauthorized, "not authenticated")
	}

	return token, nil
}

// HasRole checks if the authenticated user has a specific role.
func HasRole(r *http.Request, role string) bool {
	roles, ok := r.Context().Value("roles").([]string)
	if !ok {
		return false
	}

	for _, r := range roles {
		if r == role {
			return true
		}
	}

	return false
}

// HasPermission checks if the authenticated user has a specific permission.
func HasPermission(r *http.Request, permission string) bool {
	permissions, ok := r.Context().Value("permissions").([]string)
	if !ok {
		return false
	}

	for _, p := range permissions {
		if p == permission {
			return true
		}
	}

	return false
}

// GetClientIP gets the client IP address considering proxies.
func GetClientIP(r *http.Request) string {
	// Check for X-Forwarded-For header
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		// X-Forwarded-For can contain multiple IPs (client, proxy1, proxy2, etc.)
		// The leftmost is the original client
		ips := strings.Split(forwardedFor, ",")
		ip := strings.TrimSpace(ips[0])
		if ip != "" {
			return ip
		}
	}

	// Check for X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If there's an error splitting, just return the RemoteAddr as is
		return r.RemoteAddr
	}

	return ip
}

// ParseQueryInt64 parses a query parameter to an int64 with a default value
func ParseQueryInt64(r *http.Request, param string, defaultValue int64) int64 {
	valueStr := r.URL.Query().Get(param)
	if valueStr == "" {
		return defaultValue
	}

	value, err := strconv.ParseInt(valueStr, 10, 64)
	if err != nil {
		return defaultValue
	}

	return value
}

// ParseQueryFloat parses a query parameter to a float64 with a default value
func ParseQueryFloat(r *http.Request, param string, defaultValue float64) float64 {
	valueStr := r.URL.Query().Get(param)
	if valueStr == "" {
		return defaultValue
	}

	value, err := strconv.ParseFloat(valueStr, 64)
	if err != nil {
		return defaultValue
	}

	return value
}

// ParseQueryInt parses a query parameter to an integer with a default value
func ParseQueryInt(r *http.Request, param string, defaultValue int) int {
	valueStr := r.URL.Query().Get(param)
	if valueStr == "" {
		return defaultValue
	}

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}

	return value
}

// ParseQueryBool parses a query parameter to a boolean with a default value
func ParseQueryBool(r *http.Request, param string, defaultValue bool) bool {
	valueStr := r.URL.Query().Get(param)
	if valueStr == "" {
		return defaultValue
	}

	// Handle various truthy values
	switch strings.ToLower(valueStr) {
	case "true", "1", "t", "yes", "y", "on":
		return true
	case "false", "0", "f", "no", "n", "off":
		return false
	default:
		return defaultValue
	}
}
