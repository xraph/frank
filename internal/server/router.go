package server

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
)

type ConfigFlags struct {
	Debug          bool   `doc:"Enable debug logging" short:"d"`
	Secure         bool   `doc:"Enable high security" short:"s" default:"true"`
	Host           string `doc:"Hostname to listen on." default:"0.0.0.0"`
	Port           int    `doc:"Port to listen on." short:"p"`
	EnableWebBuild bool   `doc:"Build react client." short:"w"`
	ConfigPath     string `doc:"Config path." short:"c"`
	Domain         string `doc:"Domain the services is running on" default:"localhost"`
}

type Router interface {
	RegisterRoutes()

	Handle(pattern string, h http.Handler)

	HumaAPI() huma.API

	// Mount attaches all routes of the implementing router to the specified parent router at the given mount path.
	Mount(parent chi.Router, mountPath string)

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

	Chi() chi.Router
}
