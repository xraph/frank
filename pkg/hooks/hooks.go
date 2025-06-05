package hooks

import (
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/gen/auth"
	"github.com/juicycleff/frank/pkg/user"
)

type AuthHooks interface {
	BeforeLogin(rsp user.LoginResult) error
	OnLogin(rsp *auth.LoginResponse) error

	BeforeLogout(rsp *ent.User) error
	OnLogout(rsp *ent.User) error

	BeforeSignup(rsp *user.CreateUserInput) error
	OnSignup(rsp *auth.LoginResponse) error

	OnAccountVerified(input auth.VerifyEmailPayload, verified bool) error

	BeforeResetPassword(user user.UpdateUserInput) error
	OnResetPassword(user user.UpdateUserInput) error
}

type OrganisationHooks interface{}

type Hooks struct {
	Auth AuthHooks
	Org  OrganisationHooks
}

func New() *Hooks {
	return &Hooks{}
}

func (h *Hooks) BeforeLogout(input *ent.User) error {
	if h.Auth == nil {
		return nil
	}

	return h.Auth.BeforeLogout(input)
}

func (h *Hooks) OnLogout(input *ent.User) error {
	if h.Auth == nil {
		return nil
	}

	return h.Auth.OnLogout(input)
}

func (h *Hooks) BeforeLogin(input user.LoginResult) error {
	if h.Auth == nil {
		return nil
	}

	return h.Auth.BeforeLogin(input)
}

func (h *Hooks) OnLogin(input *auth.LoginResponse) error {
	if h.Auth == nil {
		return nil
	}
	return h.Auth.OnLogin(input)
}

func (h *Hooks) BeforeSignup(input *user.CreateUserInput) error {
	if h.Auth == nil {
		return nil
	}

	return h.Auth.BeforeSignup(input)
}

func (h *Hooks) OnSignup(input *auth.LoginResponse) error {
	if h.Auth == nil {
		return nil
	}

	return h.Auth.OnSignup(input)
}

func (h *Hooks) OnAccountVerified(input auth.VerifyEmailPayload, verified bool) error {
	if h.Auth == nil {
		return nil
	}

	return h.Auth.OnAccountVerified(input, verified)
}
