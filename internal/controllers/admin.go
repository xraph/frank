package controllers

import (
	"context"

	"github.com/juicycleff/frank/gen/admin"
	"goa.design/clue/log"
)

// admin service example implementation.
// The example methods log the requests and return zero values.
type adminsrvc struct{}

// NewAdmin returns the admin service implementation.
func NewAdmin() admin.Service {
	return &adminsrvc{}
}

// Render the home page
func (s *adminsrvc) Home(ctx context.Context) (err error) {
	log.Printf(ctx, "admin.home")
	return
}
