package routes

import (
	"github.com/danielgtaylor/huma/v2"
	"github.com/juicycleff/frank/internal/di"
)

// RegisterPersonalUserAPI registers all authentication-related endpoints
func RegisterPersonalUserAPI(group huma.API, di di.Container) {
	authCtrl := &authController{
		group: group,
		di:    di,
	}

	registerAuthStatus(group, authCtrl)
}
