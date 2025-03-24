package router

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

type FrankRouter interface {
	RegisterRoutes()

	// Handler returns the HTTP handler
	Handler() http.Handler

	// Group adds a new route group
	Group(fn func(r chi.Router))

	// Route adds a new route group with a pattern
	Route(pattern string, fn func(r chi.Router))

	// Use appends a middleware to the chain
	Use(middleware ...func(http.Handler) http.Handler)

	// Method adds a method-specific route
	Method(method, pattern string, handler http.HandlerFunc)

	// NotFound sets the not found handler
	NotFound(handler http.HandlerFunc)

	// MethodNotAllowed sets the method not allowed handler
	MethodNotAllowed(handler http.HandlerFunc)
}
