package oauth

import (
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/logging"
)

type Service interface {
	Token() TokenService
	OAuth() OAuthService
	Client() ClientService
}

type service struct {
	tokenService  TokenService
	oauthService  OAuthService
	clientService ClientService
}

func NewService(repo repository.Repository, crypto crypto.Util, logger logging.Logger) Service {
	tokService := NewTokenService(repo.OAuth(), repo.User(), logger)
	cliService := NewClientService(repo.OAuth(), logger)
	oatService := NewOAuthService(repo.OAuth(), repo.User(), logger)

	return &service{
		oauthService:  oatService,
		clientService: cliService,
		tokenService:  tokService,
	}
}

func (s *service) Token() TokenService {
	return s.tokenService
}

func (s *service) OAuth() OAuthService {
	return s.oauthService
}

func (s *service) Client() ClientService {
	return s.clientService
}
