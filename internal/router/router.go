package router

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

type FrankRouter interface {
	RegisterRoutes()

	// HandleFunc registers a new route with a pattern and an associated HTTP handler function.
	HandleFunc(pattern string, handler http.HandlerFunc)

	// Handler returns the HTTP handler
	Handler() http.Handler

	// Handle registers a route with the specified pattern and associates it with an HTTP handler.
	Handle(pattern string, h http.Handler)

	// Mount attaches all routes of the implementing router to the specified parent router at the given mount path.
	Mount(parent chi.Router, mountPath string)

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

	// BuildPath constructs an absolute path by appending the given relative path to the base path of the router.
	BuildPath(relativePath string) string
}
