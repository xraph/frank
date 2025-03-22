package controllers

import (
	"context"
	"fmt"

	"github.com/juicycleff/frank/gen/webhooks"
	"goa.design/clue/log"
	"goa.design/goa/v3/security"
)

// webhooks service example implementation.
// The example methods log the requests and return zero values.
type webhookssrvc struct{}

// NewWebhooks returns the webhooks service implementation.
func NewWebhooks() webhooks.Service {
	return &webhookssrvc{}
}

// JWTAuth implements the authorization logic for service "webhooks" for the
// "jwt" security scheme.
func (s *webhookssrvc) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	//
	// TBD: add authorization logic.
	//
	// In case of authorization failure this function should return
	// one of the generated error structs, e.g.:
	//
	//    return ctx, myservice.MakeUnauthorizedError("invalid token")
	//
	// Alternatively this function may return an instance of
	// goa.ServiceError with a Name field value that matches one of
	// the design error names, e.g:
	//
	//    return ctx, goa.PermanentError("unauthorized", "invalid token")
	//
	return ctx, fmt.Errorf("not implemented")
}

// List webhooks
func (s *webhookssrvc) List(ctx context.Context, p *webhooks.ListPayload) (res *webhooks.ListResult, err error) {
	res = &webhooks.ListResult{}
	log.Printf(ctx, "webhooks.list")
	return
}

// Create a new webhook
func (s *webhookssrvc) Create(ctx context.Context, p *webhooks.CreatePayload) (res *webhooks.WebhookSecretResponse, err error) {
	res = &webhooks.WebhookSecretResponse{}
	log.Printf(ctx, "webhooks.create")
	return
}

// Get webhook by ID
func (s *webhookssrvc) Get(ctx context.Context, p *webhooks.GetPayload) (res *webhooks.WebhookResponse, err error) {
	res = &webhooks.WebhookResponse{}
	log.Printf(ctx, "webhooks.get")
	return
}

// Update webhook
func (s *webhookssrvc) Update(ctx context.Context, p *webhooks.UpdatePayload) (res *webhooks.WebhookResponse, err error) {
	res = &webhooks.WebhookResponse{}
	log.Printf(ctx, "webhooks.update")
	return
}

// Delete webhook
func (s *webhookssrvc) Delete(ctx context.Context, p *webhooks.DeletePayload) (err error) {
	log.Printf(ctx, "webhooks.delete")
	return
}

// Manually trigger a webhook event
func (s *webhookssrvc) TriggerEvent(ctx context.Context, p *webhooks.TriggerEventPayload) (res *webhooks.WebhookEventResponse, err error) {
	res = &webhooks.WebhookEventResponse{}
	log.Printf(ctx, "webhooks.trigger_event")
	return
}

// List webhook events
func (s *webhookssrvc) ListEvents(ctx context.Context, p *webhooks.ListEventsPayload) (res *webhooks.ListEventsResult, err error) {
	res = &webhooks.ListEventsResult{}
	log.Printf(ctx, "webhooks.list_events")
	return
}

// Replay a webhook event
func (s *webhookssrvc) ReplayEvent(ctx context.Context, p *webhooks.ReplayEventPayload) (res *webhooks.WebhookEventResponse, err error) {
	res = &webhooks.WebhookEventResponse{}
	log.Printf(ctx, "webhooks.replay_event")
	return
}

// Receive webhook callbacks from external sources
func (s *webhookssrvc) Receive(ctx context.Context, p *webhooks.ReceivePayload) (res *webhooks.ReceiveResult, err error) {
	res = &webhooks.ReceiveResult{}
	log.Printf(ctx, "webhooks.receive")
	return
}
