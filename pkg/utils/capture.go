package utils

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// CaptureResponseWriter is a wrapper around http.ResponseWriter that captures
// the status code and response body for further processing
type CaptureResponseWriter struct {
	http.ResponseWriter
	StatusCode int
	Body       *bytes.Buffer
}

// NewCaptureResponseWriter creates a new response writer that captures the response
func NewCaptureResponseWriter(w http.ResponseWriter) *CaptureResponseWriter {
	return &CaptureResponseWriter{
		ResponseWriter: w,
		StatusCode:     http.StatusOK,
		Body:           &bytes.Buffer{},
	}
}

// WriteHeader captures the status code and calls the wrapped ResponseWriter
func (crw *CaptureResponseWriter) WriteHeader(code int) {
	crw.StatusCode = code
	// Don't write to the underlying writer yet
}

// Write captures the response body and returns the length, but doesn't write to the underlying writer
func (crw *CaptureResponseWriter) Write(b []byte) (int, error) {
	return crw.Body.Write(b)
}

// Header returns the header map from the wrapped ResponseWriter
func (crw *CaptureResponseWriter) Header() http.Header {
	return crw.ResponseWriter.Header()
}

// InjectCSRFToken injects a CSRF token into a JSON response
func InjectCSRFToken(w http.ResponseWriter, originalResponse []byte, statusCode int, token string) error {
	// Parse the existing response as JSON
	var response map[string]interface{}
	if err := json.Unmarshal(originalResponse, &response); err != nil {
		return err
	}

	// Add the token to the response
	response["csrf_token"] = token

	// Marshal back to JSON
	modifiedResponse, err := json.Marshal(response)
	if err != nil {
		return err
	}

	// Write the modified response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(modifiedResponse)

	return nil
}
