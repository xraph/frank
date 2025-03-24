package session

import (
	"context"
	"fmt"

	"github.com/gorilla/sessions"
)

// GoaMiddleware middleware for Goa 3
// func GoaMiddleware() func(http.Handler) http.Handler {
// 	return func(next http.Handler) http.Handler {
// 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			// Get session
// 			session, err := sessionStore.Get(r, "my-app-session")
// 			if err != nil {
// 				http.Error(w, err.Error(), http.StatusInternalServerError)
// 				return
// 			}
//
// 			// Add session to context
// 			ctx := context.WithValue(r.Context(), "session", session)
// 			r = r.WithContext(ctx)
//
// 			// Continue with next handler
// 			next.ServeHTTP(w, r)
//
// 			// Save session (handle any dynamic changes)
// 			if err := session.Save(r, w); err != nil {
// 				log.Printf("Error saving session: %v", err)
// 			}
// 		})
// 	}
// }

// GetSession Helper to get session from context
func GetSession(ctx context.Context) (*sessions.Session, bool) {
	session, ok := ctx.Value("session").(*sessions.Session)
	return session, ok
}

// SetSessionField Helper to set a dynamic field in the session
func SetSessionField(ctx context.Context, key string, value interface{}) error {
	session, ok := GetSession(ctx)
	if !ok {
		return fmt.Errorf("no session found in context")
	}

	session.Values[key] = value
	return nil
}

// GetSessionField Helper to get a dynamic field from the session
func GetSessionField(ctx context.Context, key string) (interface{}, bool) {
	session, ok := GetSession(ctx)
	if !ok {
		return nil, false
	}

	value, exists := session.Values[key]
	return value, exists
}
