package hooks

import (
	"github.com/juicycleff/frank/internal/model"
)

type AuthHooks interface {
	BeforeLogin(rsp model.LoginResponse) error
	OnLogin(rsp *model.LoginResponse) error

	BeforeLogout(rsp *model.User) error
	OnLogout(rsp *model.User) error

	BeforeSignup(rsp *model.RegisterRequest) error
	OnSignup(rsp *model.LoginResponse) error

	OnAccountVerified(input model.VerificationResponse, verified bool) error

	BeforeResetPassword(user model.PasswordResetRequest) error
	OnResetPassword(user model.PasswordResetRequest) error
}

type OrganisationHooks interface{}

type Hooks struct {
	Auth AuthHooks
	Org  OrganisationHooks
}

func New() *Hooks {
	return &Hooks{}
}

func (h *Hooks) BeforeLogout(input *model.User) error {
	if h.Auth == nil {
		return nil
	}

	return h.Auth.BeforeLogout(input)
}

func (h *Hooks) OnLogout(input *model.User) error {
	if h.Auth == nil {
		return nil
	}

	return h.Auth.OnLogout(input)
}

func (h *Hooks) BeforeLogin(input model.LoginResponse) error {
	if h.Auth == nil {
		return nil
	}

	return h.Auth.BeforeLogin(input)
}

func (h *Hooks) OnLogin(input *model.LoginResponse) error {
	if h.Auth == nil {
		return nil
	}
	return h.Auth.OnLogin(input)
}

func (h *Hooks) BeforeSignup(input *model.RegisterRequest) error {
	if h.Auth == nil {
		return nil
	}

	return h.Auth.BeforeSignup(input)
}

func (h *Hooks) OnSignup(input *model.LoginResponse) error {
	if h.Auth == nil {
		return nil
	}

	return h.Auth.OnSignup(input)
}

func (h *Hooks) OnAccountVerified(input model.VerificationResponse, verified bool) error {
	if h.Auth == nil {
		return nil
	}

	return h.Auth.OnAccountVerified(input, verified)
}
